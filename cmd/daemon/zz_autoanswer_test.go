// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/dataexchange"
)

// TestAutoAnswerReplyHook_LargeBodyNotTruncated proves the reply-on-connection
// read is NOT capped at the old 1 MiB limit: a body well over 1 MiB is returned
// in full, so a large directory reply is delivered byte-for-byte like a
// dial-back would.
func TestAutoAnswerReplyHook_LargeBodyNotTruncated(t *testing.T) {
	const size = 3 << 20 // 3 MiB, well past the retired 1 MiB cap
	big := strings.Repeat("x", size)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("message") == "" {
			t.Error("reply hook did not forward the message query param")
		}
		_, _ = w.Write([]byte(big))
	}))
	defer srv.Close()

	hook := newAutoAnswerReplyHook(srv.URL, &http.Client{Timeout: 10 * time.Second})
	rt, body, ok := hook(dataexchange.TypeAutoAnswer, []byte("/data"))
	if !ok {
		t.Fatal("hook returned ok=false for a valid large body")
	}
	if rt != dataexchange.TypeText {
		t.Errorf("reply type = %d, want TypeText", rt)
	}
	if len(body) != size {
		t.Fatalf("reply truncated: got %d bytes, want %d", len(body), size)
	}
}

// TestAutoAnswerReplyHook_EmptyAndError: an empty body or a transport error
// yields ok=false (no reply on the connection → the sender falls back).
func TestAutoAnswerReplyHook_EmptyAndError(t *testing.T) {
	// Empty body (e.g. /dispatch 204 for a dropped message).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	hook := newAutoAnswerReplyHook(srv.URL, &http.Client{Timeout: 5 * time.Second})
	if _, _, ok := hook(dataexchange.TypeAutoAnswer, []byte("prose")); ok {
		t.Error("empty body should yield ok=false")
	}
	srv.Close()

	// Transport error (server gone).
	if _, _, ok := hook(dataexchange.TypeAutoAnswer, []byte("/data")); ok {
		t.Error("transport error should yield ok=false")
	}

	// Non-200 with a non-empty body (e.g. 400 "missing message") must NOT be
	// delivered as a reply.
	errSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "missing message", http.StatusBadRequest)
	}))
	defer errSrv.Close()
	h2 := newAutoAnswerReplyHook(errSrv.URL, &http.Client{Timeout: 5 * time.Second})
	if _, body, ok := h2(dataexchange.TypeAutoAnswer, []byte("/data")); ok {
		t.Errorf("a 400 response must yield ok=false, got body=%q", body)
	}
}
