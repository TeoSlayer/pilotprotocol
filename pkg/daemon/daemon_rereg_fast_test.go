package daemon

import (
	"errors"
	"testing"
)

func TestIsRegistryRejectingUsErr(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("registry: node 1: node not found"), true},
		{errors.New("node 42: node not found"), true},
		{errors.New("registry: signature verification failed"), true},
		{errors.New("signature verification failed"), true},
		{errors.New("heartbeat: connection refused"), false},
		{errors.New("i/o timeout"), false},
		{errors.New("registry: request failed"), false},
		{errors.New("registry: hostname \"agent-b\" not found"), false}, // hostname lookup, not heartbeat
	}
	for _, tc := range cases {
		if got := isRegistryRejectingUsErr(tc.err); got != tc.want {
			t.Errorf("isRegistryRejectingUsErr(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}
