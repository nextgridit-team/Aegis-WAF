package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type connectionDeadlineRecorder struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
}

func (w *connectionDeadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	w.deadlines = append(w.deadlines, deadline)
	return nil
}

func TestConnectionExpiredUpstreamErrorDeadline(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusInternalServerError} {
		for _, duration := range []bool{false, true} {
			t.Run(fmt.Sprintf("status%d/duration%t", status, duration), func(t *testing.T) {
				state := &connectionRequestState{enforce: true, idle: time.Hour}
				state.durationExceeded.Store(duration)
				state.idleExceeded.Store(!duration)
				recorder := &connectionDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
				writer := &statusWriter{ResponseWriter: recorder, limits: state}
				writer.WriteHeader(status)
				_, _ = writer.Write([]byte("upstream error"))
				_, _ = writer.Write([]byte("continued upstream error"))
				if len(recorder.deadlines) < 3 {
					t.Fatalf("missing per-write deadlines: %v", recorder.deadlines)
				}
				for _, deadline := range recorder.deadlines {
					if deadline.IsZero() || deadline.After(time.Now()) {
						t.Fatalf("expired upstream status %d received a future deadline: %v", status, deadline)
					}
				}
			})
		}
	}
}

func TestConnectionGatewayTimeoutDeadlineGrace(t *testing.T) {
	for _, cause := range []error{errConnectionIdle, errConnectionDuration} {
		t.Run(cause.Error(), func(t *testing.T) {
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			state := &connectionRequestState{enforce: true, idle: time.Hour, cancel: cancel}
			state.idleExceeded.Store(errors.Is(cause, errConnectionIdle))
			state.durationExceeded.Store(errors.Is(cause, errConnectionDuration))
			cancel(cause)
			request := httptest.NewRequest(http.MethodGet, "http://gateway.test/", nil)
			request = request.WithContext(context.WithValue(ctx, connectionRequestKey{}, state))
			recorder := &connectionDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
			writer := &statusWriter{ResponseWriter: recorder, limits: state}
			state.writer = recorder
			target, _ := url.Parse("http://upstream.test")
			proxy := newSiteProxy(target, Site{TrafficProfile: "api"}, HeaderSettings{})
			before := time.Now()
			proxy.ErrorHandler(writer, request, cause)
			after := time.Now()
			if recorder.Code != http.StatusGatewayTimeout || !strings.Contains(recorder.Body.String(), `"error":"upstream_`) {
				t.Fatalf("gateway timeout JSON not delivered: %d %s", recorder.Code, recorder.Body.String())
			}
			grace := state.gatewayErrorDeadline
			if grace.Before(before) || grace.After(after.Add(time.Second)) {
				t.Fatalf("gateway error grace must be at most one second: %v", grace)
			}
			// A concurrent idle expiry must not poison the gateway response after
			// its headers have started, even if duration caused the first expiry.
			state.lastProgress = before.Add(-2 * time.Hour)
			state.expireIdle()
			for _, deadline := range recorder.deadlines {
				if !deadline.Equal(grace) {
					t.Fatalf("gateway error write lost fixed grace: %v, want %v", deadline, grace)
				}
			}
			state.allowGatewayTimeoutResponse()
			_, _ = writer.Write([]byte("more"))
			if !state.gatewayErrorDeadline.Equal(grace) || !recorder.deadlines[len(recorder.deadlines)-1].Equal(grace) {
				t.Fatal("gateway timeout grace slides with repeated writes")
			}
			// An already elapsed grace must remain elapsed, even on later writes.
			state.gatewayErrorDeadline = before.Add(-time.Second)
			_, _ = writer.Write([]byte("late"))
			if !recorder.deadlines[len(recorder.deadlines)-1].Equal(state.gatewayErrorDeadline) {
				t.Fatal("late gateway write extended its expired grace")
			}
		})
	}
}

func TestConnectionGatewayTimeoutGraceRequiresUnstartedResponse(t *testing.T) {
	state := &connectionRequestState{enforce: true, idle: time.Hour}
	state.idleExceeded.Store(true)
	state.responseStarted.Store(true)
	state.allowGatewayTimeoutResponse()
	if !state.gatewayErrorDeadline.IsZero() {
		t.Fatal("gateway error granted grace after upstream headers")
	}
	recorder := &connectionDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	state.writeDeadline(recorder, http.StatusGatewayTimeout)
	if recorder.deadlines[0].After(time.Now()) {
		t.Fatal("gateway timeout extended an already started upstream response")
	}
}
