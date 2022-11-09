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

package server

import (
	"context"
	"time"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/cloud"
	"github.com/gravitational/teleport/lib/cloud/azure"
	"github.com/gravitational/teleport/lib/services"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v3"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/gravitational/trace"
)

// AzureInstances contains information about discovered Azure virtual machines.
type AzureInstances struct {
	// Region is the Azure region where the instances are located.
	Region string
	// SubscriptionID is the subscription ID for the instances.
	SubscriptionID string
	// ResourceGroup is the resource group for the instances.
	ResourceGroup string
	// ScriptName is the name of the script to execute on the instances to
	// install Teleport.
	ScriptName string
	// Parameters are the parameters passed to the installation script.
	Parameters map[string]string
	// Instances is a list of discovered Azure virtual machines.
	Instances []*armcompute.VirtualMachine
}

// NewAzureWatcher creates a new Azure watcher instance.
func NewAzureWatcher(ctx context.Context, matchers []services.AzureMatcher, clients cloud.Clients) (*Watcher[AzureInstances], error) {
	cancelCtx, cancelFn := context.WithCancel(ctx)
	watcher := Watcher[AzureInstances]{
		fetchers:      []Fetcher[AzureInstances]{},
		ctx:           cancelCtx,
		cancel:        cancelFn,
		fetchInterval: time.Minute,
		InstancesC:    make(chan AzureInstances),
	}
	for _, matcher := range matchers {
		for _, subscription := range matcher.Subscriptions {
			for _, resourceGroup := range matcher.ResourceGroups {
				cl, err := clients.GetAzureVirtualMachinesClient(subscription)
				if err != nil {
					return nil, trace.Wrap(err)
				}
				fetcher := newAzureInstanceFetcher(azureFetcherConfig{
					Matcher:       matcher,
					Subscription:  subscription,
					ResourceGroup: resourceGroup,
					AzureClient:   cl,
				})
				watcher.fetchers = append(watcher.fetchers, fetcher)
			}
		}
	}
	return &watcher, nil
}

type azureFetcherConfig struct {
	Matcher       services.AzureMatcher
	Subscription  string
	ResourceGroup string
	AzureClient   azure.VirtualMachinesClient
}

type azureInstanceFetcher struct {
	Azure         azure.VirtualMachinesClient
	Regions       []string
	Subscription  string
	ResourceGroup string
	Labels        types.Labels
	Parameters    map[string]string
}

func newAzureInstanceFetcher(cfg azureFetcherConfig) *azureInstanceFetcher {
	return &azureInstanceFetcher{
		Azure:         cfg.AzureClient,
		Regions:       cfg.Matcher.Regions,
		Subscription:  cfg.Subscription,
		ResourceGroup: cfg.ResourceGroup,
		Labels:        cfg.Matcher.ResourceTags,
		Parameters: map[string]string{
			"token":      cfg.Matcher.Params.JoinToken,
			"scriptName": cfg.Matcher.Params.ScriptName,
		},
	}
}

// GetInstances fetches all Azure virtual machines matching configured filters.
func (f *azureInstanceFetcher) GetInstances(ctx context.Context) ([]AzureInstances, error) {
	instancesByRegion := make(map[string][]*armcompute.VirtualMachine)
	for _, region := range f.Regions {
		instancesByRegion[region] = []*armcompute.VirtualMachine{}
	}

	vms, err := f.Azure.ListVirtualMachines(ctx, f.ResourceGroup)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	for _, vm := range vms {
		location := aws.StringValue(vm.Location)
		if _, ok := instancesByRegion[location]; !ok {
			continue
		}
		vmTags := make(map[string]string, len(vm.Tags))
		for key, value := range vm.Tags {
			vmTags[key] = aws.StringValue(value)
		}
		if match, _, _ := services.MatchLabels(f.Labels, vmTags); !match {
			continue
		}
		instancesByRegion[location] = append(instancesByRegion[location], vm)
	}

	var instances []AzureInstances
	for region, vms := range instancesByRegion {
		if len(vms) > 0 {
			instances = append(instances, AzureInstances{
				SubscriptionID: f.Subscription,
				Region:         region,
				ResourceGroup:  f.ResourceGroup,
				Instances:      vms,
			})
		}
	}

	return instances, nil
}
