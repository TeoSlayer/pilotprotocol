// SPDX-License-Identifier: AGPL-3.0-or-later

package coreapi_test

import (
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/coreapi"
)

func TestPluginRecoveredPanicCountAndReset(t *testing.T) {
	// Not parallel — touches a package-level counter.
	coreapi.ResetPluginRecoveredPanicCountForTest()
	if got := coreapi.PluginRecoveredPanicCount(); got != 0 {
		t.Fatalf("after reset = %d, want 0", got)
	}

	// Induce a panic and let RecoverPlugin swallow it.
	func() {
		defer coreapi.RecoverPlugin("test-plugin", "test-op", nil, nil)
		panic("synthetic")
	}()
	if got := coreapi.PluginRecoveredPanicCount(); got != 1 {
		t.Errorf("after one panic = %d, want 1", got)
	}

	// Another with onPanic callback exercised.
	called := false
	func() {
		defer coreapi.RecoverPlugin("p2", "op", nil, func(_ any) { called = true })
		panic("two")
	}()
	if !called {
		t.Errorf("onPanic callback not invoked")
	}
	if got := coreapi.PluginRecoveredPanicCount(); got != 2 {
		t.Errorf("after two panics = %d, want 2", got)
	}

	// Reset works after non-zero count.
	coreapi.ResetPluginRecoveredPanicCountForTest()
	if got := coreapi.PluginRecoveredPanicCount(); got != 0 {
		t.Errorf("second reset = %d, want 0", got)
	}
}

func TestRecoverPlugin_NoPanicIsNoOp(t *testing.T) {
	t.Parallel()
	// The early-return path when recover() returns nil. No counter bump.
	before := coreapi.PluginRecoveredPanicCount()
	func() {
		defer coreapi.RecoverPlugin("clean", "op", nil, nil)
	}()
	if got := coreapi.PluginRecoveredPanicCount(); got != before {
		t.Errorf("counter changed without a panic: %d → %d", before, got)
	}
}

// fakeBusPanics publishes that itself panics — RecoverPlugin must
// shield itself from a nested publisher panic.
type fakeBusPanics struct{}

func (fakeBusPanics) Publish(string, map[string]any)                  { panic("nested-publish-panic") }
func (fakeBusPanics) Subscribe(string) (<-chan coreapi.Event, func()) { return nil, func() {} }

func TestRecoverPlugin_NestedPublishPanicSwallowed(t *testing.T) {
	// Not parallel — touches counter.
	coreapi.ResetPluginRecoveredPanicCountForTest()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("nested publish panic escaped: %v", r)
		}
	}()
	func() {
		defer coreapi.RecoverPlugin("p", "op", fakeBusPanics{}, nil)
		panic("trigger")
	}()
	if got := coreapi.PluginRecoveredPanicCount(); got != 1 {
		t.Errorf("counter = %d, want 1", got)
	}
}

func TestRecoverPlugin_NestedOnPanicSwallowed(t *testing.T) {
	// Not parallel — touches counter.
	coreapi.ResetPluginRecoveredPanicCountForTest()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("nested onPanic panic escaped: %v", r)
		}
	}()
	func() {
		defer coreapi.RecoverPlugin("p", "op", nil, func(_ any) { panic("nested-cb-panic") })
		panic("trigger")
	}()
	if got := coreapi.PluginRecoveredPanicCount(); got != 1 {
		t.Errorf("counter = %d, want 1", got)
	}
}
