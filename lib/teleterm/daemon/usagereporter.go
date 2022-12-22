// Copyright 2022 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package daemon

import (
	"context"
	"github.com/gravitational/teleport/lib/usagereporter"
	"net/http"
	"time"

	"github.com/bufbuild/connect-go"
	"github.com/google/uuid"
	"github.com/gravitational/teleport/lib/defaults"
	prehogapi "github.com/gravitational/teleport/lib/prehog/gen/prehog/v1alpha"
	prehogclient "github.com/gravitational/teleport/lib/prehog/gen/prehog/v1alpha/prehogv1alphaconnect"
	api "github.com/gravitational/teleport/lib/teleterm/api/protogen/golang/v1"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/trace"
)

const (
	// minBatchSize determines the size at which a batch is sent
	// regardless of elapsed time
	minBatchSize = 25

	// maxBatchSize is the largest batch size that will be sent to
	// the server; batches larger than this will be split into multiple
	// requests.
	maxBatchSize = 50

	// maxBatchAge is the maximum age a batch may reach before
	// being flushed, regardless of the batch size
	maxBatchAge = time.Minute * 30

	// maxBufferSize is the maximum size to which the event buffer
	// may grow. Events submitted once this limit is reached will be discarded.
	// Events that were in the submission queue that fail to submit may also be
	// discarded when requeued.
	maxBufferSize = 100

	// submitDelay is a mandatory delay added to each batch submission
	// to avoid spamming the prehog instance.
	submitDelay = time.Second * 1

	// submitDelay is a mandatory delay added to each batch submission
	// to avoid spamming the prehog instance.
	retryAttempts = 1
)

func NewConnectUsageReporter(ctx context.Context) (*usagereporter.UsageReporter[prehogapi.SubmitConnectEventRequest], error) {
	submitter, err := newRealPrehogSubmitter(ctx, "https://localhost:8443") // TODO: change the address before merge
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return usagereporter.NewUsageReporter(&usagereporter.Options[prehogapi.SubmitConnectEventRequest]{
		Submit:        submitter,
		MinBatchSize:  minBatchSize,
		MaxBatchSize:  maxBatchSize,
		MaxBufferSize: maxBufferSize,
		MaxBatchAge:   maxBatchAge,
		SubmitDelay:   submitDelay,
		RetryAttempts: retryAttempts,
	}), nil
}

func newRealPrehogSubmitter(ctx context.Context, prehogEndpoint string) (usagereporter.SubmitFunc[prehogapi.SubmitConnectEventRequest], error) {
	httpClient := &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2:   true,
			Proxy:               http.ProxyFromEnvironment,
			IdleConnTimeout:     defaults.HTTPIdleTimeout,
			MaxIdleConns:        defaults.HTTPMaxIdleConns,
			MaxIdleConnsPerHost: defaults.HTTPMaxConnsPerHost,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 5 * time.Second,
	}

	client := prehogclient.NewConnectReportingServiceClient(httpClient, prehogEndpoint)

	return func(reporter *usagereporter.UsageReporter[prehogapi.SubmitConnectEventRequest], events []*usagereporter.SubmittedEvent[prehogapi.SubmitConnectEventRequest]) ([]*usagereporter.SubmittedEvent[prehogapi.SubmitConnectEventRequest], error) {
		var failed []*usagereporter.SubmittedEvent[prehogapi.SubmitConnectEventRequest]
		var errors []error

		// Note: the backend doesn't support batching at the moment.
		for _, event := range events {
			// Note: this results in retrying the entire batch, which probably
			// isn't ideal.
			req := connect.NewRequest(event.Event)
			if _, err := client.SubmitConnectEvent(ctx, req); err != nil {
				errors = append(errors, err)
			}
		}

		return failed, trace.NewAggregate(errors...)
	}, nil
}

func (s *Service) ReportUsageEvent(req *api.ReportEventRequest) error {
	event, err := convertAndAnonymizeApiEvent(req)
	if err != nil {
		return trace.Wrap(err)
	}
	s.usageReporter.AddEventsToQueue(event)
	return nil
}

func convertAndAnonymizeApiEvent(event *api.ReportEventRequest) (*prehogapi.SubmitConnectEventRequest, error) {
	prehogEvent := event.Event

	// non-anonymized
	switch _ := prehogEvent.GetEvent().(type) {
	case *api.SubmitConnectEventRequest_ConnectUserJobRoleUpdateEvent:
		return prehogEvent, nil
	}

	//anonymized
	anonymizer, err := newClusterAnonymizer(event.GetAuthClusterId()) // authClusterId is sent with each event that needs to be anonymized
	if err != nil {
		return nil, trace.Wrap(err)
	}
	switch e := prehogEvent.GetEvent().(type) {
	case *api.SubmitConnectEventRequest_ConnectLogin:
		e.ConnectLogin.ClusterName = anonymizer.AnonymizeString(e.ConnectLogin.ClusterName)
		e.ConnectLogin.UserName = anonymizer.AnonymizeString(e.ConnectLogin.UserName)
		return prehogEvent, nil
	case *api.SubmitConnectEventRequest_ConnectProtocolRun:
		e.ConnectProtocolRun.ClusterName = anonymizer.AnonymizeString(e.ConnectProtocolRun.ClusterName)
		e.ConnectProtocolRun.UserName = anonymizer.AnonymizeString(e.ConnectProtocolRun.UserName)
		return prehogEvent, nil
	case *api.SubmitConnectEventRequest_ConnectAccessRequestCreate:
		e.ConnectAccessRequestCreate.ClusterName = anonymizer.AnonymizeString(e.ConnectAccessRequestCreate.ClusterName)
		e.ConnectAccessRequestCreate.UserName = anonymizer.AnonymizeString(e.ConnectAccessRequestCreate.UserName)
		return prehogEvent, nil
	case *api.SubmitConnectEventRequest_ConnectAccessRequestReview:
		e.ConnectAccessRequestReview.ClusterName = anonymizer.AnonymizeString(e.ConnectAccessRequestReview.ClusterName)
		e.ConnectAccessRequestReview.UserName = anonymizer.AnonymizeString(e.ConnectAccessRequestReview.UserName)
		return prehogEvent, nil
	case *api.SubmitConnectEventRequest_ConnectAccessRequestAssumeRole:
		e.ConnectAccessRequestAssumeRole.ClusterName = anonymizer.AnonymizeString(e.ConnectAccessRequestAssumeRole.ClusterName)
		e.ConnectAccessRequestAssumeRole.UserName = anonymizer.AnonymizeString(e.ConnectAccessRequestAssumeRole.UserName)
		return prehogEvent, nil
	case *api.SubmitConnectEventRequest_ConnectFileTransferRunEvent:
		e.ConnectFileTransferRunEvent.ClusterName = anonymizer.AnonymizeString(e.ConnectFileTransferRunEvent.ClusterName)
		e.ConnectFileTransferRunEvent.UserName = anonymizer.AnonymizeString(e.ConnectFileTransferRunEvent.UserName)
		return prehogEvent, nil
	}

	return nil, trace.BadParameter("unexpected Event usage type %T", event)
}

func newClusterAnonymizer(authClusterId string) (utils.Anonymizer, error) {
	_, err := uuid.Parse(authClusterId)
	if err != nil {
		return nil, trace.BadParameter("Invalid auth cluster ID %s", authClusterId)
	}
	return utils.NewHMACAnonymizer(authClusterId)
}
