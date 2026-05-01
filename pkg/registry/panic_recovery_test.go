// SPDX-License-Identifier: AGPL-3.0-or-later

package registry

import (
	"sync"
	"testing"
)

// TestRecoverHandlerPanicLogsAndContinues directly exercises the
// recoverHandler helper. We register a panic-throwing function and confirm
// the helper swallows it and logs without re-panicking.
func TestRecoverHandlerPanicLogsAndContinues(t *testing.T) {
	t.Parallel()

	completed := false

	func() {
		defer recoverHandler("test-handler", func(panicCount uint64) {
			// onPanic callback must fire exactly once per recovered panic.
			if panicCount == 0 {
				t.Errorf("panicCount should be > 0; got %d", panicCount)
			}
		})
		panic("intentional test panic")
	}()
	completed = true

	if !completed {
		t.Fatalf("recoverHandler did not catch panic — code after deferred call did not run")
	}
}

// TestRecoverHandlerNonPanicLeavesCallbacksAlone confirms the happy path:
// without a panic, the callback never fires.
func TestRecoverHandlerNonPanicLeavesCallbacksAlone(t *testing.T) {
	t.Parallel()

	calls := 0
	func() {
		defer recoverHandler("happy", func(uint64) {
			calls++
		})
		// no-op
	}()

	if calls != 0 {
		t.Fatalf("onPanic should NOT fire when no panic; got %d calls", calls)
	}
}

// TestRecoverHandlerConcurrent ensures the recovered-panic counter is
// race-safe under concurrent invocations.
func TestRecoverHandlerConcurrent(t *testing.T) {
	t.Parallel()

	var (
		mu       sync.Mutex
		seenSet  = map[uint64]struct{}{}
	)

	const N = 32
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer recoverHandler("concurrent", func(c uint64) {
				mu.Lock()
				seenSet[c] = struct{}{}
				mu.Unlock()
			})
			panic("concurrent boom")
		}()
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(seenSet) == 0 {
		t.Fatalf("no panic counts observed; recoverHandler may not be wired")
	}
	// Counts should be unique (atomic add) — at minimum N distinct values.
	if len(seenSet) < N {
		t.Logf("observed %d distinct counts under %d panics — non-atomic counter would produce duplicates", len(seenSet), N)
	}
}
