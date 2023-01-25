/*
Copyright 2023 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package auth

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/coreos/go-oidc"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"go.mozilla.org/pkcs7"
	"golang.org/x/exp/slices"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/cloud/azure"
	"github.com/gravitational/teleport/lib/utils"
)

const azureAccessTokenAudience = "https://management.azure.com/"

// Structs for unmarshaling attested data. Schema can be found at
// https://learn.microsoft.com/en-us/azure/virtual-machines/linux/instance-metadata-service?tabs=linux#response-2

type signedAttestedData struct {
	Encoding  string `json:"encoding"`
	Signature string `json:"signature"`
}

type plan struct {
	Name      string `json:"name"`
	Product   string `json:"product"`
	Publisher string `json:"publisher"`
}

type timestamp struct {
	CreatedOn string `json:"createdOn"`
	ExpiresOn string `json:"expiresOn"`
}

type attestedData struct {
	LicenseType    string    `json:"licenseType"`
	Nonce          string    `json:"nonce"`
	Plan           plan      `json:"plan"`
	Timestamp      timestamp `json:"timestamp"`
	ID             string    `json:"vmId"`
	SubscriptionID string    `json:"subscriptionId"`
	SKU            string    `json:"sku"`
}

type accessTokenClaims struct {
	jwt.Claims
	ResourceID string `json:"xms_mirid"`
	TenantID   string `json:"tid"`
	Version    string `json:"ver"`
}

type azureVerifyTokenFunc func(ctx context.Context, rawIDToken string) (*accessTokenClaims, error)

type azureRegisterConfig struct {
	clock    clockwork.Clock
	certs    []*x509.Certificate
	verify   azureVerifyTokenFunc
	vmClient azure.VirtualMachinesClient
}

func azureVerifyFuncFromOIDCVerifier(cfg *oidc.Config) azureVerifyTokenFunc {
	return func(ctx context.Context, rawIDToken string) (*accessTokenClaims, error) {
		token, err := jwt.ParseSigned(rawIDToken)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		// Need to get the tenant ID before we verify so we can construct the issuer URL.
		var unverifiedClaims accessTokenClaims
		if err := token.UnsafeClaimsWithoutVerification(&unverifiedClaims); err != nil {
			return nil, trace.Wrap(err)
		}
		provider, err := oidc.NewProvider(ctx, fmt.Sprintf("https://sts.windows.net/%v/", unverifiedClaims.TenantID))
		if err != nil {
			return nil, trace.Wrap(err)
		}
		verifiedToken, err := provider.Verifier(cfg).Verify(ctx, rawIDToken)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		var tokenClaims accessTokenClaims
		if err := verifiedToken.Claims(&tokenClaims); err != nil {
			return nil, trace.Wrap(err)
		}
		return &tokenClaims, nil
	}
}

func (cfg *azureRegisterConfig) CheckAndSetDefaults(ctx context.Context) error {
	if cfg.clock == nil {
		cfg.clock = clockwork.NewRealClock()
	}
	if cfg.verify == nil {
		oidcConfig := &oidc.Config{
			ClientID: azureAccessTokenAudience,
			Now:      cfg.clock.Now,
		}
		cfg.verify = azureVerifyFuncFromOIDCVerifier(oidcConfig)
	}

	if cfg.certs == nil {
		certs, err := getAzureCerts()
		if err != nil {
			return trace.Wrap(err)
		}
		cfg.certs = certs
	}
	return nil
}

type azureRegisterOption func(cfg *azureRegisterConfig)

// parseAndVeryAttestedData verifies that an attested data document was signed
// by Azure. If verification is successful, it returns the ID of the VM that
// produced the document.
func parseAndVerifyAttestedData(adBytes []byte, challenge string, certs []*x509.Certificate) (string, error) {
	var signedAD signedAttestedData
	if err := utils.FastUnmarshal(adBytes, &signedAD); err != nil {
		return "", trace.Wrap(err)
	}
	if signedAD.Encoding != "pkcs7" {
		return "", trace.AccessDenied("unsupported signature type: %v", signedAD.Encoding)
	}

	sigPEM := "-----BEGIN PKCS7-----\n" + signedAD.Signature + "\n-----END PKCS7-----"
	sigBER, _ := pem.Decode([]byte(sigPEM))
	if sigBER == nil {
		return "", trace.AccessDenied("unable to decode attested data document")
	}

	p7, err := pkcs7.Parse(sigBER.Bytes)
	if err != nil {
		return "", trace.Wrap(err)
	}
	fixAzureSigningAlgorithm(p7)

	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}

	if err := p7.VerifyWithChain(pool); err != nil {
		return "", trace.Wrap(err)
	}

	var ad attestedData
	if err := utils.FastUnmarshal(p7.Content, &ad); err != nil {
		return "", trace.Wrap(err)
	}

	if ad.Nonce != challenge {
		return "", trace.AccessDenied("challenge is missing or does not match")
	}

	return ad.ID, nil
}

// verifyVMIdentity verifies that the provided access token came from the
// correct Azure VM.
func verifyVMIdentity(ctx context.Context, cfg *azureRegisterConfig, accessToken, vmID string, requestStart time.Time) (*azure.VirtualMachine, error) {
	tokenClaims, err := cfg.verify(ctx, accessToken)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	expectedIssuer, err := url.JoinPath("https://sts.windows.net", tokenClaims.TenantID, "/")
	if err != nil {
		return nil, trace.Wrap(err)
	}
	// v2 tokens have the version appended to the issuer.
	if tokenClaims.Version == "2.0" {
		expectedIssuer, err = url.JoinPath(expectedIssuer, "2.0")
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}

	expectedClaims := jwt.Expected{
		Issuer:   expectedIssuer,
		Audience: jwt.Audience{azureAccessTokenAudience},
		Time:     requestStart,
	}

	if err := tokenClaims.Validate(expectedClaims); err != nil {
		return nil, trace.Wrap(err)
	}

	rsID, err := arm.ParseResourceID(tokenClaims.ResourceID)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	vmClient := cfg.vmClient
	if vmClient == nil {
		tokenCredential := azure.NewStaticCredential(azcore.AccessToken{
			Token:     accessToken,
			ExpiresOn: tokenClaims.Expiry.Time(),
		})
		var err error
		vmClient, err = azure.NewVirtualMachinesClient(rsID.SubscriptionID, tokenCredential, nil)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}

	resourceID, err := arm.ParseResourceID(tokenClaims.ResourceID)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var vm *azure.VirtualMachine

	// If the token is from the system-assigned managed identity, the resource ID
	// is for the VM itself and we can use it to look up the VM.
	if slices.Contains(resourceID.ResourceType.Types, "virtualMachine") {
		vm, err = vmClient.Get(ctx, tokenClaims.ResourceID)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		if vm.VMID != vmID {
			return nil, trace.AccessDenied("vm ID does not match")
		}

		// If the token is from a user-assigned managed identity, the resource ID is
		// for the identity and we need to look the VM up by VM ID.
	} else {
		vm, err = vmClient.GetByVMID(ctx, resourceID.ResourceGroupName, vmID)
		if err != nil {
			if trace.IsNotFound(err) {
				return nil, trace.AccessDenied("no VM found with matching VM ID")
			}
			return nil, trace.Wrap(err)
		}
	}

	return vm, nil
}

func checkAzureAllowRules(vm *azure.VirtualMachine, allowRules []*types.ProvisionTokenSpecV2Azure_Rule) error {
	for _, rule := range allowRules {
		if len(rule.Subscription) > 0 {
			if rule.Subscription != vm.Subscription {
				continue
			}
		}
		if len(rule.ResourceGroups) > 0 {
			if !slices.Contains(rule.ResourceGroups, vm.ResourceGroup) {
				continue
			}
		}
		return nil
	}
	return trace.AccessDenied("instance did not match any allow rules")
}

func (a *Server) checkAzureRequest(ctx context.Context, challenge string, req *proto.RegisterUsingAzureMethodRequest, cfg *azureRegisterConfig) error {
	requestStart := a.clock.Now()
	tokenName := req.RegisterUsingTokenRequest.Token
	provisionToken, err := a.GetToken(ctx, tokenName)
	if err != nil {
		return trace.Wrap(err)
	}
	if provisionToken.GetJoinMethod() != types.JoinMethodAzure {
		return trace.AccessDenied("this token does not support the Azure join method")
	}

	vmID, err := parseAndVerifyAttestedData(req.AttestedData, challenge, cfg.certs)
	if err != nil {
		return trace.Wrap(err)
	}

	vm, err := verifyVMIdentity(ctx, cfg, req.AccessToken, vmID, requestStart)
	if err != nil {
		return trace.Wrap(err)
	}

	token, ok := provisionToken.(*types.ProvisionTokenV2)
	if !ok {
		return trace.BadParameter("azure join method only supports ProvisionTokenV2, '%T' was provided", provisionToken)
	}

	if err := checkAzureAllowRules(vm, token.Spec.Azure.Allow); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

func generateAzureChallenge() (string, error) {
	challenge, err := generateChallenge(base64.RawURLEncoding, 24)
	return challenge, trace.Wrap(err)
}

// RegisterUsingAzureMethod registers the caller using the Azure join method
// and returns signed certs to join the cluster.
//
// The caller must provide a ChallengeResponseFunc which returns a
// *proto.RegisterUsingAzureMethodRequest with a signed attested data document
// including the challenge as a nonce.
func (a *Server) RegisterUsingAzureMethod(ctx context.Context, challengeResponse client.RegisterAzureChallengeResponseFunc, opts ...azureRegisterOption) (*proto.Certs, error) {
	cfg := &azureRegisterConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	if err := cfg.CheckAndSetDefaults(ctx); err != nil {
		return nil, trace.Wrap(err)
	}

	clientAddr, ok := ctx.Value(ContextClientAddr).(net.Addr)
	if !ok {
		return nil, trace.BadParameter("logic error: client address was not set")
	}
	challenge, err := generateAzureChallenge()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	req, err := challengeResponse(challenge)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	req.RegisterUsingTokenRequest.RemoteAddr = clientAddr.String()
	if err := req.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	provisionToken, err := a.checkTokenJoinRequestCommon(ctx, req.RegisterUsingTokenRequest)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := a.checkAzureRequest(ctx, challenge, req, cfg); err != nil {
		return nil, trace.Wrap(err)
	}

	certs, err := a.generateCerts(ctx, provisionToken, req.RegisterUsingTokenRequest, nil)
	return certs, trace.Wrap(err)
}

// fixAzureSigningAlgorithm fixes a mismatch between the object IDs of the
// hashing algorithm sent by Azure vs the ones expected by the pkcs7 library.
// Specifically, Azure (incorrectly?) sends a [digest encryption algorithm]
// where the pkcs7 structure's [signerInfo] expects a [digest algorithm].
//
// [signerInfo]: https://www.rfc-editor.org/rfc/rfc2315#section-6.4
// [digest algorithm]: https://www.rfc-editor.org/rfc/rfc2315#section-6.3
// [digest encryption algorithm]: https://www.rfc-editor.org/rfc/rfc2315#section-6.4
func fixAzureSigningAlgorithm(p7 *pkcs7.PKCS7) {
	for i, signer := range p7.Signers {
		if signer.DigestAlgorithm.Algorithm.Equal(pkcs7.OIDEncryptionAlgorithmRSASHA256) {
			p7.Signers[i].DigestAlgorithm.Algorithm = pkcs7.OIDDigestAlgorithmSHA256
		}
	}
}
