// SPDX-License-Identifier: AGPL-3.0-or-later

package authority

import (
	"errors"
	"fmt"
)

var (
	ErrPersistence              = errors.New("authority: durable state unavailable")
	ErrStateConflict            = errors.New("authority: conflicting durable state")
	ErrUnknownPolicyPublication = errors.New("authority: unknown policy publication")
)

func persistenceError(operation string, err error) error {
	if errors.Is(err, ErrStateConflict) {
		return fmt.Errorf("authority: %s: %w", operation, err)
	}
	return fmt.Errorf("%w: %s: %v", ErrPersistence, operation, err)
}
