package account

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/TeoSlayer/pilotprotocol/internal/fsutil"
)

// Account holds persisted account information alongside the identity file.
type Account struct {
	Email string `json:"email"`
}

// Save writes the account to disk atomically with 0600 permissions.
func Save(path string, acct *Account) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create account dir: %w", err)
	}
	data, err := json.MarshalIndent(acct, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal account: %w", err)
	}
	if err := fsutil.AtomicWrite(path, data); err != nil {
		return fmt.Errorf("write account: %w", err)
	}
	// Ensure 0600 permissions
	return os.Chmod(path, 0600)
}

// Load reads an account from disk. Returns nil, nil if the file does not exist.
func Load(path string) (*Account, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read account: %w", err)
	}
	var acct Account
	if err := json.Unmarshal(data, &acct); err != nil {
		return nil, fmt.Errorf("unmarshal account: %w", err)
	}
	return &acct, nil
}

// PathFromIdentity returns the account file path derived from an identity file path.
// If identity is "/var/lib/pilot/identity.json", returns "/var/lib/pilot/account.json".
func PathFromIdentity(identityPath string) string {
	return filepath.Join(filepath.Dir(identityPath), "account.json")
}
