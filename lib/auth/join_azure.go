/*
Copyright 2022 Gravitational, Inc.

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
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/coreos/go-oidc"
	"github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/cloud/azure"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"go.mozilla.org/pkcs7"
	"golang.org/x/exp/slices"
	"gopkg.in/square/go-jose.v2/jwt"
)

const azureAccessTokenAudience = "https://management.azure.com/"

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

func withCerts(certs []*x509.Certificate) azureRegisterOption {
	return func(cfg *azureRegisterConfig) {
		cfg.certs = certs
	}
}

func withVerifyFunc(verify azureVerifyTokenFunc) azureRegisterOption {
	return func(cfg *azureRegisterConfig) {
		cfg.verify = verify
	}
}

func withVMClient(vmClient azure.VirtualMachinesClient) azureRegisterOption {
	return func(cfg *azureRegisterConfig) {
		cfg.vmClient = vmClient
	}
}

// parseAndVeryAttestedData verifies that an attested data document was signed
// by Azure.
func parseAndVerifyAttestedData(adBytes []byte, challenge string, certs []*x509.Certificate) (string, error) {
	var signedAD signedAttestedData
	if err := json.Unmarshal(adBytes, &signedAD); err != nil {
		return "", trace.Wrap(err)
	}
	if signedAD.Encoding != "pkcs7" {
		return "", trace.AccessDenied("unsupported signature type: %v", signedAD.Encoding)
	}

	sigPEM := fmt.Sprintf("-----BEGIN PKCS7-----\n%s\n-----END PKCS7-----", string(signedAD.Signature))
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
	if err := json.Unmarshal(p7.Content, &ad); err != nil {
		return "", trace.Wrap(err)
	}

	if ad.Nonce != challenge {
		return "", trace.AccessDenied("challenge is missing or does not match")
	}

	return ad.ID, nil
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

	tokenClaims, err := cfg.verify(ctx, req.AccessToken)
	if err != nil {
		return trace.Wrap(err)
	}

	expectedIssuer := fmt.Sprintf("https://sts.windows.net/%v/", tokenClaims.TenantID)
	if tokenClaims.Version == "2.0" {
		expectedIssuer += "2.0" // TODO(atburke): need extra "/" ?
	}

	expectedClaims := jwt.Expected{
		Issuer:   expectedIssuer,
		Audience: jwt.Audience{azureAccessTokenAudience},
		Time:     requestStart,
	}

	if err := tokenClaims.Validate(expectedClaims); err != nil {
		return trace.Wrap(err)
	}

	rsID, err := arm.ParseResourceID(tokenClaims.ResourceID)
	if err != nil {
		return trace.Wrap(err)
	}

	vmClient := cfg.vmClient
	if vmClient == nil {
		tokenCredential := azure.NewStaticCredential(azcore.AccessToken{
			Token:     req.AccessToken,
			ExpiresOn: tokenClaims.Expiry.Time(),
		})
		var err error
		vmClient, err = azure.NewVirtualMachinesClient(rsID.SubscriptionID, tokenCredential, nil)
		if err != nil {
			return trace.Wrap(err)
		}
	}

	vm, err := vmClient.Get(ctx, tokenClaims.ResourceID)
	if err != nil {
		return trace.Wrap(err)
	}
	if vm.VMID != vmID {
		return trace.AccessDenied("vm ID does not match")
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
func fixAzureSigningAlgorithm(p7 *pkcs7.PKCS7) {
	for i, signer := range p7.Signers {
		if signer.DigestAlgorithm.Algorithm.Equal(pkcs7.OIDEncryptionAlgorithmRSASHA256) {
			p7.Signers[i].DigestAlgorithm.Algorithm = pkcs7.OIDDigestAlgorithmSHA256
		}
	}
}
