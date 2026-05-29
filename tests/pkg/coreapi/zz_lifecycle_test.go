// SPDX-License-Identifier: AGPL-3.0-or-later

package coreapi_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/pilot-protocol/common/coreapi"
)

type fakeService struct {
	name      string
	order     int
	startErr  error
	stopErr   error
	startedAt int // sequence number, set by harness
}

func (f *fakeService) Name() string { return f.name }
func (f *fakeService) Order() int   { return f.order }
func (f *fakeService) Start(ctx context.Context, deps coreapi.Deps) error {
	return f.startErr
}
func (f *fakeService) Stop(ctx context.Context) error { return f.stopErr }

func TestServiceRegistry_StartOrder(t *testing.T) {
	t.Parallel()
	sr := &coreapi.ServiceRegistry{}
	a := &fakeService{name: "a", order: 200}
	b := &fakeService{name: "b", order: 100}
	c := &fakeService{name: "c", order: 50}
	for _, s := range []coreapi.Service{a, b, c} {
		if err := sr.Register(s); err != nil {
			t.Fatalf("register %s: %v", s.Name(), err)
		}
	}
	if err := sr.StartAll(context.Background(), coreapi.Deps{}); err != nil {
		t.Fatalf("StartAll: %v", err)
	}
	got := sr.All()
	want := []string{"c", "b", "a"}
	for i, s := range got {
		if s.Name() != want[i] {
			t.Errorf("position %d: got %s, want %s", i, s.Name(), want[i])
		}
	}
}

func TestServiceRegistry_StartFailureAborts(t *testing.T) {
	t.Parallel()
	sr := &coreapi.ServiceRegistry{}
	a := &fakeService{name: "a", order: 10}
	boom := &fakeService{name: "boom", order: 20, startErr: errors.New("boom")}
	c := &fakeService{name: "c", order: 30}
	for _, s := range []coreapi.Service{a, boom, c} {
		_ = sr.Register(s)
	}
	err := sr.StartAll(context.Background(), coreapi.Deps{})
	if err == nil || err.Error() != "boom" {
		t.Fatalf("want boom, got %v", err)
	}
	// `c` should NOT have been started after boom failed; verify by
	// calling StopAll and checking only the started ones rolled back.
	// (We can't directly observe started state, but the registry should
	// not crash and Stop should return nil on the un-started services.)
	if err := sr.StopAll(context.Background()); err != nil {
		t.Errorf("StopAll after partial start: %v", err)
	}
}

func TestServiceRegistry_StopReverseOrder(t *testing.T) {
	t.Parallel()
	sr := &coreapi.ServiceRegistry{}
	stops := []string{}
	a := &recordingStop{name: "a", order: 10, stops: &stops}
	b := &recordingStop{name: "b", order: 20, stops: &stops}
	c := &recordingStop{name: "c", order: 30, stops: &stops}
	for _, s := range []coreapi.Service{a, b, c} {
		_ = sr.Register(s)
	}
	_ = sr.StartAll(context.Background(), coreapi.Deps{})
	_ = sr.StopAll(context.Background())
	want := []string{"c", "b", "a"}
	if fmt.Sprint(stops) != fmt.Sprint(want) {
		t.Errorf("stop order: got %v, want %v", stops, want)
	}
}

func TestServiceRegistry_RegisterAfterStart(t *testing.T) {
	t.Parallel()
	sr := &coreapi.ServiceRegistry{}
	_ = sr.Register(&fakeService{name: "a", order: 10})
	_ = sr.StartAll(context.Background(), coreapi.Deps{})
	if err := sr.Register(&fakeService{name: "late", order: 50}); !errors.Is(err, coreapi.ErrRegistryStarted) {
		t.Errorf("want ErrRegistryStarted, got %v", err)
	}
}

type recordingStop struct {
	name  string
	order int
	stops *[]string
}

func (r *recordingStop) Name() string                                       { return r.name }
func (r *recordingStop) Order() int                                         { return r.order }
func (r *recordingStop) Start(ctx context.Context, deps coreapi.Deps) error { return nil }
func (r *recordingStop) Stop(ctx context.Context) error {
	*r.stops = append(*r.stops, r.name)
	return nil
}
