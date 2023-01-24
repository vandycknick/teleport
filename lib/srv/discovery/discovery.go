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

package discovery

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v3"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/cloud"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/srv/discovery/common"
	"github.com/gravitational/teleport/lib/srv/discovery/fetchers"
	"github.com/gravitational/teleport/lib/srv/discovery/fetchers/db"
	"github.com/gravitational/teleport/lib/srv/server"
)

// Config provides configuration for the discovery server.
type Config struct {
	// Clients is an interface for retrieving cloud clients.
	Clients cloud.Clients
	// AWSMatchers is a list of AWS EC2 matchers.
	AWSMatchers []services.AWSMatcher
	// AzureMatchers is a list of Azure matchers to discover resources.
	AzureMatchers []services.AzureMatcher
	// GCPMatchers is a list of GCP matchers to discover resources.
	GCPMatchers []services.GCPMatcher
	// Emitter is events emitter, used to submit discrete events
	Emitter apievents.Emitter
	// AccessPoint is a discovery access point
	AccessPoint auth.DiscoveryAccessPoint
	// Log is the logger.
	Log logrus.FieldLogger
	// onDatabaseReconcile is called after each database resource reconciliation.
	onDatabaseReconcile func()
}

func (c *Config) CheckAndSetDefaults() error {
	if c.Clients == nil {
		c.Clients = cloud.NewClients()
	}
	if len(c.AWSMatchers) == 0 && len(c.AzureMatchers) == 0 && len(c.GCPMatchers) == 0 {
		return trace.BadParameter("no matchers configured for discovery")
	}
	if c.Emitter == nil {
		return trace.BadParameter("no Emitter configured for discovery")
	}
	if c.AccessPoint == nil {
		return trace.BadParameter("no AccessPoint configured for discovery")
	}
	if c.Log == nil {
		c.Log = logrus.New()
	}

	c.Log = c.Log.WithField(trace.Component, teleport.ComponentDiscovery)
	c.AzureMatchers = services.SimplifyAzureMatchers(c.AzureMatchers)
	return nil
}

// Server is a discovery server, used to discover cloud resources for
// inclusion in Teleport
type Server struct {
	*Config

	ctx context.Context
	// cancelfn is used with ctx when stopping the discovery server
	cancelfn context.CancelFunc
	// nodeWatcher is a node watcher.
	nodeWatcher *services.NodeWatcher

	// ec2Watcher periodically retrieves EC2 instances.
	ec2Watcher *server.Watcher
	// ec2Installer is used to start the installation process on discovered EC2 nodes
	ec2Installer *server.SSMInstaller
	// azureWatcher periodically retrieves Azure virtual machines.
	azureWatcher *server.Watcher
	// kubeFetchers holds all kubernetes fetchers for Azure and other clouds.
	kubeFetchers []common.Fetcher
	// databaseFetchers holds all database fetchers.
	databaseFetchers []common.Fetcher
}

// New initializes a discovery Server
func New(ctx context.Context, cfg *Config) (*Server, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	localCtx, cancelfn := context.WithCancel(ctx)
	s := &Server{
		Config:   cfg,
		ctx:      localCtx,
		cancelfn: cancelfn,
	}

	if err := s.initAWSWatchers(cfg.AWSMatchers); err != nil {
		return nil, trace.Wrap(err)
	}

	if err := s.initAzureWatchers(ctx, cfg.AzureMatchers); err != nil {
		return nil, trace.Wrap(err)
	}

	if err := s.initGCPWatchers(ctx, cfg.GCPMatchers); err != nil {
		return nil, trace.Wrap(err)
	}

	if s.ec2Watcher != nil || s.azureWatcher != nil {
		if err := s.initTeleportNodeWatcher(); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	return s, nil
}

// initAWSWatchers starts AWS resource watchers based on types provided.
func (s *Server) initAWSWatchers(matchers []services.AWSMatcher) error {
	ec2Matchers, otherMatchers := splitAWSMatchers(matchers, func(matcherType string) bool {
		return matcherType == services.AWSMatcherEC2
	})

	// start ec2 watchers
	var err error
	if len(ec2Matchers) > 0 {
		s.ec2Watcher, err = server.NewEC2Watcher(s.ctx, ec2Matchers, s.Clients)
		if err != nil {
			return trace.Wrap(err)
		}
		s.ec2Installer = server.NewSSMInstaller(server.SSMInstallerConfig{
			Emitter: s.Emitter,
		})
	}

	// Add database fetchers.
	databaseMatchers, otherMatchers := splitAWSMatchers(otherMatchers, db.IsAWSMatcherType)
	if len(databaseMatchers) > 0 {
		databaseFetchers, err := db.MakeAWSFetchers(s.Clients, databaseMatchers)
		if err != nil {
			return trace.Wrap(err)
		}
		s.databaseFetchers = append(s.databaseFetchers, databaseFetchers...)
	}

	// Add kube fetchers.
	for _, matcher := range otherMatchers {
		for _, t := range matcher.Types {
			for _, region := range matcher.Regions {
				switch t {
				case services.AWSMatcherEKS:
					client, err := s.Clients.GetAWSEKSClient(region)
					if err != nil {
						return trace.Wrap(err)
					}
					fetcher, err := fetchers.NewEKSFetcher(
						fetchers.EKSFetcherConfig{
							Client:       client,
							Region:       region,
							FilterLabels: matcher.Tags,
							Log:          s.Log,
						},
					)
					if err != nil {
						return trace.Wrap(err)
					}
					s.kubeFetchers = append(s.kubeFetchers, fetcher)
				}
			}
		}
	}

	return nil
}

// initAzureWatchers starts Azure resource watchers based on types provided.
func (s *Server) initAzureWatchers(ctx context.Context, matchers []services.AzureMatcher) error {
	vmMatchers, otherMatchers := splitAzureMatchers(matchers, func(matcherType string) bool {
		return matcherType == services.AzureMatcherVM
	})

	// VM watcher.
	if len(vmMatchers) > 0 {
		var err error
		s.azureWatcher, err = server.NewAzureWatcher(s.ctx, vmMatchers, s.Clients)
		if err != nil {
			return trace.Wrap(err)
		}
	}

	// Add database fetchers.
	databaseMatchers, otherMatchers := splitAzureMatchers(otherMatchers, db.IsAzureMatcherType)
	if len(databaseMatchers) > 0 {
		databaseFetchers, err := db.MakeAzureFetchers(s.Clients, databaseMatchers)
		if err != nil {
			return trace.Wrap(err)
		}
		s.databaseFetchers = append(s.databaseFetchers, databaseFetchers...)
	}

	// Add kube fetchers.
	for _, matcher := range otherMatchers {
		subscriptions, err := s.getAzureSubscriptions(ctx, matcher.Subscriptions)
		if err != nil {
			return trace.Wrap(err)
		}
		for _, subscription := range subscriptions {
			for _, t := range matcher.Types {
				switch t {
				case services.AzureMatcherKubernetes:
					kubeClient, err := s.Clients.GetAzureKubernetesClient(subscription)
					if err != nil {
						return trace.Wrap(err)
					}
					fetcher, err := fetchers.NewAKSFetcher(fetchers.AKSFetcherConfig{
						Client:         kubeClient,
						Regions:        matcher.Regions,
						FilterLabels:   matcher.ResourceTags,
						ResourceGroups: matcher.ResourceGroups,
						Log:            s.Log,
					})
					if err != nil {
						return trace.Wrap(err)
					}
					s.kubeFetchers = append(s.kubeFetchers, fetcher)
				}
			}
		}
	}
	return nil
}

// initGCPWatchers starts GCP resource watchers based on types provided.
func (s *Server) initGCPWatchers(ctx context.Context, matchers []services.GCPMatcher) error {
	// return early if there are no matchers as GetGCPGKEClient causes
	// an error if there are no credentials present
	if len(matchers) == 0 {
		return nil
	}
	kubeClient, err := s.Clients.GetGCPGKEClient(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	for _, matcher := range matchers {
		for _, projectID := range matcher.ProjectIDs {
			for _, location := range matcher.Locations {
				for _, t := range matcher.Types {
					switch t {
					case services.GCPMatcherKubernetes:
						fetcher, err := fetchers.NewGKEFetcher(fetchers.GKEFetcherConfig{
							Client:       kubeClient,
							Location:     location,
							FilterLabels: matcher.Tags,
							ProjectID:    projectID,
							Log:          s.Log,
						})
						if err != nil {
							return trace.Wrap(err)
						}
						s.kubeFetchers = append(s.kubeFetchers, fetcher)
					}
				}
			}
		}
	}
	return nil
}

func (s *Server) filterExistingEC2Nodes(instances *server.EC2Instances) {
	nodes := s.nodeWatcher.GetNodes(func(n services.Node) bool {
		labels := n.GetAllLabels()
		_, accountOK := labels[types.AWSAccountIDLabel]
		_, instanceOK := labels[types.AWSInstanceIDLabel]
		return accountOK && instanceOK
	})

	var filtered []*ec2.Instance
outer:
	for _, inst := range instances.Instances {
		for _, node := range nodes {
			match := types.MatchLabels(node, map[string]string{
				types.AWSAccountIDLabel:  instances.AccountID,
				types.AWSInstanceIDLabel: aws.StringValue(inst.InstanceId),
			})
			if match {
				continue outer
			}
		}
		filtered = append(filtered, inst)
	}
	instances.Instances = filtered
}

func genEC2InstancesLogStr(instances []*ec2.Instance) string {
	return genInstancesLogStr(instances, func(i *ec2.Instance) string {
		return aws.StringValue(i.InstanceId)
	})
}

func genAzureInstancesLogStr(instances []*armcompute.VirtualMachine) string {
	return genInstancesLogStr(instances, func(i *armcompute.VirtualMachine) string {
		return aws.StringValue(i.Name)
	})
}

func genInstancesLogStr[T any](instances []T, getID func(T) string) string {
	var logInstances strings.Builder
	for idx, inst := range instances {
		if idx == 10 || idx == (len(instances)-1) {
			logInstances.WriteString(getID(inst))
			break
		}
		logInstances.WriteString(getID(inst) + ", ")
	}
	if len(instances) > 10 {
		logInstances.WriteString(fmt.Sprintf("... + %d instance IDs truncated", len(instances)-10))
	}

	return fmt.Sprintf("[%s]", logInstances.String())
}

func (s *Server) handleEC2Instances(instances *server.EC2Instances) error {
	// TODO(amk): once agentless node inventory management is
	//            implemented, create nodes after a successful SSM run

	ec2Client, err := s.Clients.GetAWSSSMClient(instances.Region)
	if err != nil {
		return trace.Wrap(err)
	}
	s.filterExistingEC2Nodes(instances)
	if len(instances.Instances) == 0 {
		return trace.NotFound("all fetched nodes already enrolled")
	}

	s.Log.Debugf("Running Teleport installation on these instances: AccountID: %s, Instances: %s",
		instances.AccountID, genEC2InstancesLogStr(instances.Instances))

	req := server.SSMRunRequest{
		DocumentName: instances.DocumentName,
		SSM:          ec2Client,
		Instances:    instances.Instances,
		Params:       instances.Parameters,
		Region:       instances.Region,
		AccountID:    instances.AccountID,
	}
	return trace.Wrap(s.ec2Installer.Run(s.ctx, req))
}

func (s *Server) handleEC2Discovery() {
	if err := s.nodeWatcher.WaitInitialization(); err != nil {
		s.Log.WithError(err).Error("Failed to initialize nodeWatcher.")
		return
	}

	go s.ec2Watcher.Run()
	for {
		select {
		case instances := <-s.ec2Watcher.InstancesC:
			ec2Instances := instances.EC2Instances
			s.Log.Debugf("EC2 instances discovered (AccountID: %s, Instances: %v), starting installation",
				instances.AccountID, genEC2InstancesLogStr(ec2Instances.Instances))

			if err := s.handleEC2Instances(ec2Instances); err != nil {
				if trace.IsNotFound(err) {
					s.Log.Debug("All discovered EC2 instances are already part of the cluster.")
				} else {
					s.Log.WithError(err).Error("Failed to enroll discovered EC2 instances.")
				}

			}
		case <-s.ctx.Done():
			s.ec2Watcher.Stop()
			return
		}
	}
}

func (s *Server) handleAzureInstances(instances *server.AzureInstances) error {
	s.Log.Error("Automatic Azure node joining not implemented")
	return nil
}

func (s *Server) handleAzureDiscovery() {
	go s.azureWatcher.Run()
	for {
		select {
		case instances := <-s.azureWatcher.InstancesC:
			azureInstances := instances.AzureInstances
			s.Log.Debugf("Azure instances discovered (SubscriptionID: %s, Instances: %v), starting installation",
				instances.SubscriptionID, genAzureInstancesLogStr(azureInstances.Instances),
			)
			if err := s.handleAzureInstances(azureInstances); err != nil {
				if trace.IsNotFound(err) {
					s.Log.Debug("All discovered Azure VMs are already part of the cluster.")
				} else {
					s.Log.WithError(err).Error("Failed to enroll discovered Azure VMs.")
				}
			}
		case <-s.ctx.Done():
			s.azureWatcher.Stop()
			return
		}
	}
}

// Start starts the discovery service.
func (s *Server) Start() error {
	if s.ec2Watcher != nil {
		go s.handleEC2Discovery()
	}
	if s.azureWatcher != nil {
		go s.handleAzureDiscovery()
	}
	if len(s.kubeFetchers) > 0 {
		if err := s.startKubeWatchers(); err != nil {
			return trace.Wrap(err)
		}
	}
	if err := s.startDatabaseWatchers(); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// Stop stops the discovery service.
func (s *Server) Stop() {
	s.cancelfn()
	if s.ec2Watcher != nil {
		s.ec2Watcher.Stop()
	}
	if s.azureWatcher != nil {
		s.azureWatcher.Stop()
	}
}

// Wait will block while the server is running.
func (s *Server) Wait() error {
	<-s.ctx.Done()
	if err := s.ctx.Err(); err != nil && err != context.Canceled {
		return trace.Wrap(err)
	}
	return nil
}

func (s *Server) getAzureSubscriptions(ctx context.Context, subs []string) ([]string, error) {
	subscriptionIds := subs
	if slices.Contains(subs, types.Wildcard) {
		subsClient, err := s.Clients.GetAzureSubscriptionClient()
		if err != nil {
			return nil, trace.Wrap(err)
		}
		subscriptionIds, err = subsClient.ListSubscriptionIDs(ctx)
		return subscriptionIds, trace.Wrap(err)
	}

	return subscriptionIds, nil
}

func (s *Server) initTeleportNodeWatcher() (err error) {
	s.nodeWatcher, err = services.NewNodeWatcher(s.ctx, services.NodeWatcherConfig{
		ResourceWatcherConfig: services.ResourceWatcherConfig{
			Component: teleport.ComponentDiscovery,
			Log:       s.Log,
			Client:    s.AccessPoint,
		},
	})

	return trace.Wrap(err)
}

// splitSlice splits a slice into two, by putting all elements that satisfy the
// provided check function in the first slice, while putting all other elements
// in the second slice.
func splitSlice(ss []string, check func(string) bool) (split, other []string) {
	for _, e := range ss {
		if check(e) {
			split = append(split, e)
		} else {
			other = append(other, e)
		}
	}
	return
}

// splitAWSMatchers splits the AWS matchers by checking the matcher types.
func splitAWSMatchers(matchers []services.AWSMatcher, matcherTypeCheck func(string) bool) (split, other []services.AWSMatcher) {
	for _, matcher := range matchers {
		splitTypes, otherTypes := splitSlice(matcher.Types, matcherTypeCheck)

		if len(splitTypes) > 0 {
			split = append(split, copyAWSMatcherWithNewTypes(matcher, splitTypes))
		}
		if len(otherTypes) > 0 {
			other = append(other, copyAWSMatcherWithNewTypes(matcher, otherTypes))
		}
	}
	return
}

// splitAzureMatchers splits the Azure matchers by checking the matcher types.
func splitAzureMatchers(matchers []services.AzureMatcher, matcherTypeCheck func(string) bool) (split, other []services.AzureMatcher) {
	for _, matcher := range matchers {
		splitTypes, otherTypes := splitSlice(matcher.Types, matcherTypeCheck)

		if len(splitTypes) > 0 {
			split = append(split, copyAzureMatcherWithNewTypes(matcher, splitTypes))
		}
		if len(otherTypes) > 0 {
			other = append(other, copyAzureMatcherWithNewTypes(matcher, otherTypes))
		}
	}
	return
}

// copyAWSMatcherWithNewTypes copies an AWS Matcher and replaces the types with newTypes
func copyAWSMatcherWithNewTypes(matcher services.AWSMatcher, newTypes []string) services.AWSMatcher {
	newMatcher := matcher
	newMatcher.Types = newTypes
	return newMatcher
}

// copyAzureMatcherWithNewTypes copies an Azure Matcher and replaces the types with newTypes.
func copyAzureMatcherWithNewTypes(matcher services.AzureMatcher, newTypes []string) services.AzureMatcher {
	newMatcher := matcher
	newMatcher.Types = newTypes
	return newMatcher
}
