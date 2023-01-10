package server

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v3"
	"github.com/aws/aws-sdk-go/aws"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/cloud/azure"
	"github.com/gravitational/trace"
	"golang.org/x/sync/errgroup"
)

// AzureInstallerConfig represents configuration for an Azure install script
// executor.
type AzureInstallerConfig struct {
	Emitter     apievents.Emitter
	AccessPoint auth.DiscoveryAccessPoint
}

// AzureInstaller handles running commands that install Teleport on Azure
// virtual machines.
type AzureInstaller struct {
	AzureInstallerConfig
}

// NewAzureInstaller returns a new Azure installer.
func NewAzureInstaller(cfg AzureInstallerConfig) *AzureInstaller {
	return &AzureInstaller{
		AzureInstallerConfig: cfg,
	}
}

// AzureRunRequest combines parameters for running commands on a set of Azure
// virtual machines.
type AzureRunRequest struct {
	Client        azure.RunCommandClient
	Instances     []*armcompute.VirtualMachine
	Params        map[string]string
	Region        string
	ResourceGroup string
	ScriptName    string
}

// Run runs a command on a set of virtual machines and then blocks until the
// commands have completed.
func (ai *AzureInstaller) Run(ctx context.Context, req AzureRunRequest) error {
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(10)
	installer, err := ai.AccessPoint.GetInstaller(ctx, req.ScriptName)
	if err != nil {
		return trace.Wrap(err)
	}

	for _, inst := range req.Instances {
		inst := inst
		g.Go(func() error {
			params := make(map[string]string, len(req.Params))
			for k, v := range req.Params {
				params[k] = v
			}

			runRequest := azure.RunCommandRequest{
				Region:        req.Region,
				ResourceGroup: req.ResourceGroup,
				VMName:        aws.StringValue(inst.Name),
				Parameters:    req.Params,
				Script:        installer.GetScript(),
			}
			return trace.Wrap(req.Client.Run(ctx, runRequest))
		})
	}
	return trace.Wrap(g.Wait())
}
