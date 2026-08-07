// SPDX-License-Identifier: AGPL-3.0-or-later

// Command control-agent is a headless reference node for Pilot's optional
// hosted control plane. It runs the same enterprisecontrol runtime as the Web4
// daemon without opening a Pilot transport, making signed fleet operations
// usable beside any agent harness. It intentionally exposes no remote shell.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/pilot-protocol/common/actionhook"
	"github.com/pilot-protocol/pilotprotocol/internal/enterprisecontrol"
	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/authority"
)

type evidenceEvent struct {
	Event          string `json:"event"`
	CommandID      string `json:"command_id,omitempty"`
	Detail         string `json:"detail,omitempty"`
	PID            int    `json:"pid"`
	RuntimeVersion string `json:"runtime_version"`
	ObservedAt     int64  `json:"observed_at"`
}

type diagnosticRecord struct {
	Version        uint16 `json:"version"`
	CommandID      string `json:"command_id"`
	Hostname       string `json:"hostname"`
	PID            int    `json:"pid"`
	UID            int    `json:"uid"`
	RuntimeVersion string `json:"runtime_version"`
	PolicyRevision uint64 `json:"policy_revision"`
	StartedAt      int64  `json:"started_at"`
	ObservedAt     int64  `json:"observed_at"`
}

func main() {
	controlPath := flag.String("enterprise-control", "", "path to the signed enterprise control attachment")
	runtimeVersion := flag.String("runtime-version", "pilot-control-agent/1.0.0", "reported runtime version")
	nodeID := flag.Uint("node-id", 1001, "reported Pilot node ID")
	poll := flag.Duration("poll-interval", 2*time.Second, "fleet control poll interval")
	evidenceDirectory := flag.String("evidence-dir", "", "owner-only directory for tangible lifecycle and diagnostic evidence")
	flag.Parse()
	if *controlPath == "" || *evidenceDirectory == "" || *poll < 250*time.Millisecond || *poll > time.Minute || *nodeID == 0 || *nodeID > uint(^uint32(0)) {
		fatalf("enterprise-control, evidence-dir, a node ID, and a 250ms-1m poll interval are required")
	}
	if err := os.MkdirAll(*evidenceDirectory, 0o700); err != nil {
		fatalf("create evidence directory: %v", err)
	}
	controls, err := enterprisecontrol.Load(*controlPath)
	if err != nil {
		fatalf("load enterprise controls: %v", err)
	}
	started := time.Now().UTC()
	if err := appendEvidence(*evidenceDirectory, evidenceEvent{Event: "startup", PID: os.Getpid(), RuntimeVersion: *runtimeVersion, ObservedAt: started.Unix()}); err != nil {
		fatalf("record startup: %v", err)
	}
	if err := runTangibleHook(context.Background(), controls, *evidenceDirectory); err != nil {
		fatalf("run tangible action hook: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	ticker := time.NewTicker(*poll)
	defer ticker.Stop()
	for {
		lifecycle, err := synchronize(ctx, controls, uint32(*nodeID), *runtimeVersion, started, *evidenceDirectory)
		if err != nil && ctx.Err() == nil {
			_, _ = fmt.Fprintf(os.Stderr, "pilot-control-agent: synchronize: %v\n", err)
		}
		switch lifecycle {
		case "restart":
			if err := appendEvidence(*evidenceDirectory, evidenceEvent{Event: "restart_requested", PID: os.Getpid(), RuntimeVersion: *runtimeVersion, ObservedAt: time.Now().UTC().Unix()}); err != nil {
				fatalf("record restart: %v", err)
			}
			executable, err := os.Executable()
			if err != nil {
				fatalf("resolve executable: %v", err)
			}
			if err := syscall.Exec(executable, os.Args, os.Environ()); err != nil {
				fatalf("restart process: %v", err)
			}
		case "shutdown":
			if err := appendEvidence(*evidenceDirectory, evidenceEvent{Event: "shutdown_requested", PID: os.Getpid(), RuntimeVersion: *runtimeVersion, ObservedAt: time.Now().UTC().Unix()}); err != nil {
				fatalf("record shutdown: %v", err)
			}
			return
		}
		select {
		case <-ctx.Done():
			_ = appendEvidence(*evidenceDirectory, evidenceEvent{Event: "signal_shutdown", PID: os.Getpid(), RuntimeVersion: *runtimeVersion, ObservedAt: time.Now().UTC().Unix()})
			return
		case <-ticker.C:
		}
	}
}

func synchronize(ctx context.Context, controls *enterprisecontrol.Runtime, nodeID uint32, runtimeVersion string, started time.Time, evidenceDirectory string) (string, error) {
	reconciliation, err := controls.ReconcileFleetControl(ctx, runtimeVersion)
	if err != nil {
		return "", err
	}
	if reconciliation.Found {
		if err := controls.ReportFleetControlAcknowledgement(ctx, reconciliation, runtimeVersion); err != nil {
			return "", err
		}
	}
	status := enterprisecontrol.FleetNodeStatus{
		NodeID: nodeID, AgentVersion: runtimeVersion, UptimeSeconds: uint64(time.Since(started).Seconds()),
		PolicyRevision: controls.CurrentPolicyRevision(ctx),
	}
	if err := controls.ReportFleetStatus(ctx, status); err != nil {
		return "", err
	}
	commands, err := controls.FleetCommands(ctx)
	if err != nil {
		return "", err
	}
	for _, command := range commands {
		outcome, detail, lifecycle := executeCommand(ctx, controls, command, runtimeVersion, started, evidenceDirectory)
		if err := controls.ReportFleetCommandResult(ctx, command.ID, outcome, detail); err != nil {
			return "", err
		}
		if err := appendEvidence(evidenceDirectory, evidenceEvent{Event: "command_result", CommandID: command.ID, Detail: string(command.Kind) + ":" + outcome + ":" + detail, PID: os.Getpid(), RuntimeVersion: runtimeVersion, ObservedAt: time.Now().UTC().Unix()}); err != nil {
			return "", err
		}
		if outcome == "succeeded" && lifecycle != "" {
			if err := controls.MarkLifecycleCommandApplied(command); err != nil {
				return "", err
			}
			return lifecycle, nil
		}
	}
	return "", nil
}

func executeCommand(ctx context.Context, controls *enterprisecontrol.Runtime, command authority.FleetCommand, runtimeVersion string, started time.Time, evidenceDirectory string) (string, string, string) {
	switch command.Kind {
	case authority.FleetCommandRefreshPolicy:
		if err := controls.RefreshRollout(ctx); err != nil {
			return "failed", "rollout_refresh_failed", ""
		}
		return "succeeded", "policy_refreshed", ""
	case authority.FleetCommandExportReceipts:
		if !controls.HasReceiptExport() {
			return "rejected", "receipt_export_unconfigured", ""
		}
		if err := controls.ExportReceiptsOnce(ctx); err != nil {
			return "failed", "receipt_export_failed", ""
		}
		return "succeeded", "receipts_exported", ""
	case authority.FleetCommandReloadControl:
		if err := controls.Reload(); err != nil {
			return "failed", "control_reload_failed", ""
		}
		return "succeeded", "control_reloaded", ""
	case authority.FleetCommandSyncState:
		if !controls.HasFleetStateSync() {
			return "rejected", "state_sync_unconfigured", ""
		}
		if _, err := controls.SyncFleetState(ctx); err != nil {
			return "failed", "state_sync_failed", ""
		}
		return "succeeded", "state_synchronized", ""
	case authority.FleetCommandDiagnostics:
		if controls.HasFleetStateSync() {
			if _, err := controls.SyncFleetState(ctx); err != nil {
				return "failed", "diagnostics_sync_failed", ""
			}
		}
		if err := writeDiagnostics(evidenceDirectory, command.ID, runtimeVersion, controls.CurrentPolicyRevision(ctx), started); err != nil {
			return "failed", "diagnostics_write_failed", ""
		}
		return "succeeded", "diagnostics_written", ""
	case authority.FleetCommandRestartRuntime:
		if controls.LifecycleCommandAlreadyApplied(command) {
			return "rejected", "already_applied", ""
		}
		return "succeeded", "restart_accepted", "restart"
	case authority.FleetCommandShutdownRuntime:
		if controls.LifecycleCommandAlreadyApplied(command) {
			return "rejected", "already_applied", ""
		}
		return "succeeded", "shutdown_accepted", "shutdown"
	default:
		return "rejected", "command_not_allowlisted", ""
	}
}

func runTangibleHook(ctx context.Context, controls *enterprisecontrol.Runtime, evidenceDirectory string) error {
	hook := controls.ActionHook()
	if hook == nil {
		return fmt.Errorf("managed action hook is not configured")
	}
	target := filepath.Join(evidenceDirectory, "hook-side-effect.txt")
	if _, err := os.Stat(target); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	content := []byte("Pilot managed action hook released this tangible file write.\n")
	digest := sha256.Sum256(content)
	envelope, err := actionhook.NewEnvelope("file.write", "workspace:control-agent/hook-side-effect.txt", hex.EncodeToString(digest[:]), "pilot.control-agent", map[string]string{"content_type": "text/plain"}, time.Now().UTC())
	if err != nil {
		return err
	}
	preflight, err := hook.BeforeAction(ctx, envelope)
	if err != nil {
		return err
	}
	if err := preflight.RequireUnconstrained(); err != nil {
		return err
	}
	if err := os.WriteFile(target, content, 0o600); err != nil {
		return err
	}
	if err := hook.AfterAction(ctx, envelope, preflight, actionhook.ObservedResult{Status: actionhook.StatusSucceeded, ObservedAt: time.Now().UTC().Unix()}); err != nil {
		return err
	}
	return appendEvidence(evidenceDirectory, evidenceEvent{Event: "managed_hook_side_effect", Detail: "file.write:allow", PID: os.Getpid(), RuntimeVersion: "pilot-control-agent/1.0.0", ObservedAt: time.Now().UTC().Unix()})
}

func writeDiagnostics(directory, commandID, runtimeVersion string, policyRevision uint64, started time.Time) error {
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	record := diagnosticRecord{Version: 1, CommandID: commandID, Hostname: hostname, PID: os.Getpid(), UID: os.Getuid(), RuntimeVersion: runtimeVersion, PolicyRevision: policyRevision, StartedAt: started.Unix(), ObservedAt: time.Now().UTC().Unix()}
	return writeSecureJSON(filepath.Join(directory, "diagnostics-"+commandID+".json"), record)
}

func appendEvidence(directory string, event evidenceEvent) error {
	path := filepath.Join(directory, "control-events.jsonl")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	encodeErr := json.NewEncoder(file).Encode(event)
	closeErr := file.Close()
	return errors.Join(encodeErr, closeErr)
}

func writeSecureJSON(path string, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func fatalf(format string, arguments ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "pilot-control-agent: "+format+"\n", arguments...)
	os.Exit(1)
}
