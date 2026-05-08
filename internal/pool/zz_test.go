// SPDX-License-Identifier: AGPL-3.0-or-later

package pool

import (
	"sync"
	"testing"
)

func TestGetSmallReturnsCorrectSize(t *testing.T) {
	t.Parallel()
	b := GetSmall()
	if b == nil {
		t.Fatal("GetSmall returned nil")
	}
	if len(*b) != SmallBufSize {
		t.Fatalf("len = %d, want %d", len(*b), SmallBufSize)
	}
	if cap(*b) < SmallBufSize {
		t.Fatalf("cap = %d, want >= %d", cap(*b), SmallBufSize)
	}
}

func TestGetLargeReturnsCorrectSize(t *testing.T) {
	t.Parallel()
	b := GetLarge()
	if b == nil {
		t.Fatal("GetLarge returned nil")
	}
	if len(*b) != LargeBufSize {
		t.Fatalf("len = %d, want %d", len(*b), LargeBufSize)
	}
	if cap(*b) < LargeBufSize {
		t.Fatalf("cap = %d, want >= %d", cap(*b), LargeBufSize)
	}
}

func TestPutGetSmallRoundTrip(t *testing.T) {
	t.Parallel()
	b := GetSmall()
	*b = (*b)[:10] // shrink len
	(*b)[0] = 0xAB
	PutSmall(b)
	// We can't guarantee we get back the same buffer, but if we do its len must be reset
	got := GetSmall()
	if len(*got) != SmallBufSize {
		t.Fatalf("recycled buffer len not reset: %d", len(*got))
	}
}

func TestPutGetLargeRoundTrip(t *testing.T) {
	t.Parallel()
	b := GetLarge()
	*b = (*b)[:1] // shrink len
	PutLarge(b)
	got := GetLarge()
	if len(*got) != LargeBufSize {
		t.Fatalf("recycled large buffer len not reset: %d", len(*got))
	}
}

func TestPutSmallNilSafe(t *testing.T) {
	t.Parallel()
	// Must not panic
	PutSmall(nil)
}

func TestPutLargeNilSafe(t *testing.T) {
	t.Parallel()
	PutLarge(nil)
}

func TestPutSmallRejectsUndersizedBuffer(t *testing.T) {
	t.Parallel()
	tiny := make([]byte, 10)
	// PutSmall checks cap < SmallBufSize and silently returns.
	// We can't directly observe it didn't enter the pool, but it must not panic.
	PutSmall(&tiny)
	// Subsequent GetSmall should still work
	b := GetSmall()
	if len(*b) != SmallBufSize {
		t.Fatalf("GetSmall after rejected PutSmall returned len=%d", len(*b))
	}
}

func TestPutLargeRejectsUndersizedBuffer(t *testing.T) {
	t.Parallel()
	tiny := make([]byte, 100)
	PutLarge(&tiny)
	b := GetLarge()
	if len(*b) != LargeBufSize {
		t.Fatalf("GetLarge after rejected PutLarge returned len=%d", len(*b))
	}
}

func TestConcurrentGetPutSmall(t *testing.T) {
	t.Parallel()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				b := GetSmall()
				if len(*b) != SmallBufSize {
					t.Errorf("len=%d", len(*b))
					return
				}
				PutSmall(b)
			}
		}()
	}
	wg.Wait()
}

func TestConcurrentGetPutLarge(t *testing.T) {
	t.Parallel()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				b := GetLarge()
				if len(*b) != LargeBufSize {
					t.Errorf("len=%d", len(*b))
					return
				}
				PutLarge(b)
			}
		}()
	}
	wg.Wait()
}

// Sanity: constants match documented sizes.
func TestBufferSizeConstants(t *testing.T) {
	t.Parallel()
	if SmallBufSize != 4096 {
		t.Errorf("SmallBufSize = %d, want 4096", SmallBufSize)
	}
	if LargeBufSize != 65535+38 {
		t.Errorf("LargeBufSize = %d, want %d (max payload + tunnel magic + header)", LargeBufSize, 65535+38)
	}
}
