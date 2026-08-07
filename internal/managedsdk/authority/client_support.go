// SPDX-License-Identifier: AGPL-3.0-or-later

package authority

import (
	"context"
	"strings"
	"unicode/utf8"
)

// StoredRollout and RolloutPersistence are the narrow persistence contract
// accepted by PolicyManager. The managed node normally uses the in-memory
// implementation; hosted persistence remains in the private control plane.
type StoredRollout struct {
	Publication      PolicyPublication
	Bundle           PolicyBundle
	Acknowledgements []PolicyAcknowledgement
	Activation       *PolicyActivation
	Withdrawal       *PolicyWithdrawal
}

type RolloutPersistence interface {
	SavePolicyPublication(context.Context, PolicyPublication, PolicyBundle) error
	AppendPolicyAcknowledgement(context.Context, PolicyAcknowledgement) error
	SavePolicyActivation(context.Context, PolicyActivation) error
	LoadRollouts(context.Context) ([]StoredRollout, error)
}

type TenantRolloutPersistence interface {
	RolloutPersistence
	LoadTenantRollouts(context.Context, string) ([]StoredRollout, error)
}

type RolloutGenerationPersistence interface {
	TenantRolloutPersistence
	RolloutGeneration(context.Context, string) (uint64, error)
}

type RolloutWithdrawalPersistence interface {
	SavePolicyWithdrawal(context.Context, PolicyWithdrawal) error
}

func boundedAuditText(value string, maximum int, allowEmpty bool) bool {
	if (!allowEmpty && strings.TrimSpace(value) == "") || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func lowerHexIdentifier(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}
