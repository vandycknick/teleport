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

package responsewriters

import (
	"errors"
	"io"
	"mime"
	"net/http"

	"github.com/gravitational/trace"
	"golang.org/x/sync/errgroup"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/streaming"
	"k8s.io/apimachinery/pkg/watch"
	restclientwatch "k8s.io/client-go/rest/watch"
)

const (
	ContentTypeHeader  = "Content-Type"
	DefaultContentType = "application/json"
)

// WatcherResponseWriter satisfies the http.ResponseWriter interface and
// once the server writes the headers and response code spins a goroutine
// that parses each event frame, decodes it and analyzes if the user
// is allowed to receive the events for that pod.
// If the user is not allowed, the event is ignored.
// If allowed, the event is encoded into the user's response.
type WatcherResponseWriter struct {
	// target is the user response writer.
	// everything written will be received by the user.
	target http.ResponseWriter
	// status holds the response code status for logging purposes.
	status int
	// group is the errorgroup used by the spinning goroutine.
	group errgroup.Group
	// pipeReader and pipeWriter are synchronous memory pipes used to forward
	// events written from the upstream server to the routine that decodes
	// them and validates if the event should be forward downstream.
	pipeReader *io.PipeReader
	pipeWriter *io.PipeWriter
	// negotiator is the client negotiator used to select the serializers based
	// on response content-type.
	negotiator runtime.ClientNegotiator
	// filter hold the filtering rules to filter events.
	filter FilterWrapper
}

// NewWatcherResponseWriter creates a new WatcherResponseWriter.
func NewWatcherResponseWriter(
	target http.ResponseWriter,
	negotiator runtime.ClientNegotiator,
	filter FilterWrapper,
) (*WatcherResponseWriter, error) {
	if err := checkWatcherRequiredFields(target, negotiator); err != nil {
		return nil, trace.Wrap(err)
	}
	reader, writer := io.Pipe()
	return &WatcherResponseWriter{
		target:     target,
		pipeReader: reader,
		pipeWriter: writer,
		negotiator: negotiator,
		filter:     filter,
	}, nil
}

// checkWatcherRequiredFields checks if the target response writer and negotiator are
// defined.
func checkWatcherRequiredFields(target http.ResponseWriter, negotiator runtime.ClientNegotiator) error {
	if target == nil {
		return trace.BadParameter("missing target ResponseWriter")
	}
	if negotiator == nil {
		return trace.BadParameter("missing negotiator")
	}
	return nil
}

// Write writes buf into the pipeWriter.
func (w *WatcherResponseWriter) Write(buf []byte) (int, error) {
	return w.pipeWriter.Write(buf)
}

// Header returns the target headers.
func (w *WatcherResponseWriter) Header() http.Header {
	return w.target.Header()
}

// WriteHeader writes the status code and headers into the target http.ResponseWriter
// and spins a go-routine that will wait for events received in w.pipeReader
// and analyze if they must be forwarded to target.
func (w *WatcherResponseWriter) WriteHeader(code int) {
	w.status = code
	w.target.WriteHeader(code)
	contentType := GetContentHeader(w.Header())
	w.group.Go(
		func() error {
			switch {
			case code == http.StatusSwitchingProtocols:
				// no-op, we've been upgraded
				return nil
			case code < http.StatusOK /* 200 */ || code > http.StatusPartialContent /* 206 */ :
				// If code is bellow 200 (OK) or higher than 206 (PartialContent), it means that
				// Kubernetes returned an error response which does not contain watch events.
				// In that case, it is safe to write it back to target and return early.
				// Some valid cases:
				// - user does not have the `watch` permission.
				// - API is unable to serve the request.
				// Logic from: https://github.com/kubernetes/client-go/blob/58ff029093df37cad9fa28778a37f11fa495d9cf/rest/request.go#L1040
				_, err := io.Copy(w.target, w.pipeReader)
				return trace.Wrap(err)
			default:
				err := w.watchDecoder(contentType, w.target, w.pipeReader)
				return trace.Wrap(err)
			}
		},
	)
}

// Status returns the http status response.
func (w *WatcherResponseWriter) Status() int {
	return w.getStatus()
}

func (w *WatcherResponseWriter) getStatus() int {
	// http.ResponseWriter implicitly sets StatusOK, if WriteHeader hasn't been
	// explicitly called.
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

// Close closes the reader part of the pipe with io.EOF and waits until
// the spinned goroutine terminates.
// After closes the writer pipe and flushes the response into target.
func (w *WatcherResponseWriter) Close() error {
	w.pipeReader.CloseWithError(io.EOF)
	err := w.group.Wait()
	w.pipeWriter.CloseWithError(io.EOF)
	w.Flush()
	return trace.Wrap(err)
}

// Flush flushes the response into the target and returns.
func (w *WatcherResponseWriter) Flush() {
	if flusher, ok := w.target.(http.Flusher); ok {
		flusher.Flush()
	}
}

// watchDecoder waits for events written into w.pipeWriter and decodes them.
// Once decoded, it checks if the user is allowed to watch the events for that pod
// and ignores or forwards them downstream depending on the result.
func (w *WatcherResponseWriter) watchDecoder(contentType string, writer io.Writer, reader io.ReadCloser) error {
	// parse mime type.
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return trace.Wrap(err)
	}
	// create a stream decoder based on mediaType.s
	objectDecoder, streamingSerializer, framer, err := w.negotiator.StreamDecoder(mediaType, params)
	if err != nil {
		return trace.Wrap(err)
	}
	// create a encoder to encode filtered requests to the user.
	encoder, err := w.negotiator.Encoder(mediaType, params)
	if err != nil {
		return trace.Wrap(err)
	}
	// create a frameReader that waits until the Kubernetes API sends the full
	// event frame.
	frameReader := framer.NewFrameReader(reader)
	defer frameReader.Close()
	// create a frameWriter that writes event frames into the user's connection.
	frameWriter := framer.NewFrameWriter(writer)
	// streamingDecoder is the decoder that parses metav1.WatchEvents from the
	// long-lived connection.
	streamingDecoder := streaming.NewDecoder(frameReader, streamingSerializer)
	defer streamingDecoder.Close()
	// create encoders
	watchEventEncoder := streaming.NewEncoder(frameWriter, streamingSerializer)
	watchEncoder := restclientwatch.NewEncoder(watchEventEncoder, encoder)
	// instantiate filterObj if available.
	var filter FilterObj
	if w.filter != nil {
		filter, err = w.filter(contentType, w.getStatus())
		if err != nil {
			return trace.Wrap(err)
		}
	}
	// wait for events received from upstream until the connection is terminated.
	for {
		eventType, obj, err := w.decodeStreamingMessage(streamingDecoder, objectDecoder)
		if errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return trace.Wrap(err)
		}

		switch obj.(type) {
		case *metav1.Status:
			// Status object is returned when the Kubernetes API returns an error and
			// should be forwarded to the user.
			// If eventType is empty, it means that status was returned without event.
			if eventType == "" {
				err = encoder.Encode(obj, writer)
				return trace.Wrap(err)
			}
			// encode the event into the target connection.
			err = watchEncoder.Encode(
				&watch.Event{
					Type:   eventType,
					Object: obj,
				},
			)

			return trace.Wrap(err)
		default:
			if filter != nil {
				// check if the event object matches the filtering criteria.
				// If it does not match, ignore the event.
				publish, err := filter.FilterObj(obj)
				if err != nil {
					return trace.Wrap(err)
				}
				if !publish {
					continue
				}
			}
			// encode the event into the target connection.
			err = watchEncoder.Encode(
				&watch.Event{
					Type:   eventType,
					Object: obj,
				},
			)
			if err != nil {
				return trace.Wrap(err)
			}
		}
	}
}

// Decode blocks until it can return the next object in the reader. Returns an error
// if the reader is closed or an object can't be decoded.
// decodeStreamingMessage blocks until it can return the next object in the reader.
// Returns an error if the reader is closed or an object can't be decoded.
func (w *WatcherResponseWriter) decodeStreamingMessage(
	streamDecoder streaming.Decoder,
	embeddedEncoder runtime.Decoder,
) (watch.EventType, runtime.Object, error) {
	var event metav1.WatchEvent
	res, gvk, err := streamDecoder.Decode(nil, &event)
	if err != nil {
		return "", nil, err
	}
	if gvk != nil {
		res.GetObjectKind().SetGroupVersionKind(*gvk)
	}
	switch res.(type) {
	case *metav1.Status:
		// Status object is returned when the Kubernetes API returns an error and
		// should be forwarded to the user.
		return "", res, nil
	default:
		switch watch.EventType(event.Type) {
		case watch.Added, watch.Modified, watch.Deleted, watch.Error, watch.Bookmark:
		default:
			return "", nil, trace.BadParameter("got invalid watch event type: %v", event.Type)
		}
		obj, gvk, err := embeddedEncoder.Decode(event.Object.Raw, nil /* defaults */, nil /* into */)
		if err != nil {
			return "", nil, trace.Wrap(err)
		}
		if gvk != nil {
			obj.GetObjectKind().SetGroupVersionKind(*gvk)
		}
		return watch.EventType(event.Type), obj, nil
	}
}
