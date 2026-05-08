// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !no_dataexchange
// +build !no_dataexchange

package dataexchange

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	internaldx "github.com/TeoSlayer/pilotprotocol/internal/dataexchange"
	"github.com/TeoSlayer/pilotprotocol/pkg/coreapi"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// ServiceConfig configures the daemon-side dataexchange handler. Both
// paths default to ~/.pilot/{received,inbox} when empty.
type ServiceConfig struct {
	ReceivedDir string
	InboxDir    string
}

// Service is the L11 plugin adapter. Daemon (L7) holds it only as
// coreapi.Service; cmd/daemon/main.go (L12) constructs it.
type Service struct {
	cfg      ServiceConfig
	listener coreapi.Listener
	deps     coreapi.Deps
	cancel   context.CancelFunc
	done     chan struct{}
	seq      atomic.Uint64
}

func NewService(cfg ServiceConfig) *Service {
	return &Service{cfg: cfg}
}

func (s *Service) Name() string { return "dataexchange" }

// Order: 110 — after handshake (~70) and the trust subsystem (~50).
func (s *Service) Order() int { return 110 }

func (s *Service) Start(ctx context.Context, deps coreapi.Deps) error {
	s.deps = deps
	ln, err := deps.Streams.Listen(protocol.PortDataExchange)
	if err != nil {
		return fmt.Errorf("dataexchange: listen on port %d: %w", protocol.PortDataExchange, err)
	}
	s.listener = ln

	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.done = make(chan struct{})
	go s.acceptLoop(runCtx)
	slog.Info("dataexchange service listening", "port", protocol.PortDataExchange)
	return nil
}

func (s *Service) Stop(ctx context.Context) error {
	if s.cancel != nil {
		s.cancel()
	}
	if s.listener != nil {
		_ = s.listener.Close()
	}
	if s.done == nil {
		return nil
	}
	select {
	case <-s.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

func (s *Service) acceptLoop(ctx context.Context) {
	defer close(s.done)
	// L11 panic boundary: a panic in Accept must not kill the plugin.
	// TODO(03-INVARIANTS.md §8): per-plugin supervisor.
	defer coreapi.RecoverPlugin("dataexchange", "acceptLoop", s.deps.Events, nil)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *Service) handleConn(ctx context.Context, conn coreapi.Stream) {
	// L11 panic boundary: tear down THIS conn only.
	defer coreapi.RecoverPlugin("dataexchange", "handleConn", s.deps.Events, nil)
	defer conn.Close()
	for {
		frame, err := internaldx.ReadFrame(conn)
		// Capture right after the IO read so receiver-side timestamps are as
		// close to the wire as possible.
		frameReceivedAtNs := time.Now().UnixNano()
		if err != nil {
			return
		}
		slog.Debug("dataexchange frame received",
			"type", internaldx.TypeName(frame.Type),
			"bytes", len(frame.Payload),
			"remote", conn.RemoteAddr())

		var saveErr error
		var ackFrame *internaldx.Frame
		switch frame.Type {
		case internaldx.TypeFile:
			if frame.Filename != "" {
				saveErr = s.saveReceivedFile(frame)
			}
		case internaldx.TypeText, internaldx.TypeJSON, internaldx.TypeBinary:
			saveErr = s.saveInboxMessage(frame, conn.RemoteAddr())
		case internaldx.TypeTrace:
			tf, tferr := internaldx.ReadTracePayload(frame)
			if tferr != nil {
				ackFrame = &internaldx.Frame{
					Type:    internaldx.TypeText,
					Payload: []byte(fmt.Sprintf("ERR trace parse: %v", tferr)),
				}
			} else {
				innerFrame := &internaldx.Frame{Type: tf.InnerType, Payload: tf.Payload}
				innerSaveErr := s.saveInboxMessage(innerFrame, conn.RemoteAddr())
				inboxWrittenAtNs := time.Now().UnixNano()
				innerAck := fmt.Sprintf("ACK %s %d bytes", internaldx.TypeName(tf.InnerType), len(tf.Payload))
				if innerSaveErr != nil {
					innerAck = fmt.Sprintf("ERR %s save failed: %v", internaldx.TypeName(tf.InnerType), innerSaveErr)
				}
				ackSentAtNs := time.Now().UnixNano()
				timingJSON, _ := json.Marshal(map[string]interface{}{
					"sent_at_ns":          tf.SentAtNs,
					"received_at_ns":      frameReceivedAtNs,
					"inbox_written_at_ns": inboxWrittenAtNs,
					"ack_sent_at_ns":      ackSentAtNs,
					"inner_ack":           innerAck,
				})
				ackFrame = &internaldx.Frame{Type: internaldx.TypeJSON, Payload: timingJSON}
			}
		}

		if ackFrame == nil {
			ackMsg := fmt.Sprintf("ACK %s %d bytes", internaldx.TypeName(frame.Type), len(frame.Payload))
			if saveErr != nil {
				ackMsg = fmt.Sprintf("ERR %s save failed: %v", internaldx.TypeName(frame.Type), saveErr)
			}
			ackFrame = &internaldx.Frame{Type: internaldx.TypeText, Payload: []byte(ackMsg)}
		}
		if err := internaldx.WriteFrame(conn, ackFrame); err != nil {
			return
		}
	}
}

// receivedDir returns the configured received-file directory or the
// default ~/.pilot/received.
func (s *Service) receivedDir() (string, error) {
	if s.cfg.ReceivedDir != "" {
		return s.cfg.ReceivedDir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home dir: %w", err)
	}
	return filepath.Join(home, ".pilot", "received"), nil
}

// inboxDir returns the configured inbox directory or the default
// ~/.pilot/inbox.
func (s *Service) inboxDir() (string, error) {
	if s.cfg.InboxDir != "" {
		return s.cfg.InboxDir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home dir: %w", err)
	}
	return filepath.Join(home, ".pilot", "inbox"), nil
}

func (s *Service) saveReceivedFile(frame *internaldx.Frame) error {
	dir, err := s.receivedDir()
	if err != nil {
		slog.Warn("save received file: cannot determine dir", "err", err)
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		slog.Warn("save received file: mkdir failed", "err", err)
		return fmt.Errorf("mkdir: %w", err)
	}

	safeName := filepath.Base(frame.Filename)
	ts := time.Now().Format("20060102-150405.000")
	seq := s.seq.Add(1)
	ext := filepath.Ext(safeName)
	base := safeName[:len(safeName)-len(ext)]
	destName := fmt.Sprintf("%s-%s-%06d%s", base, ts, seq, ext)
	destPath := filepath.Join(dir, destName)

	if err := os.WriteFile(destPath, frame.Payload, 0600); err != nil {
		_ = os.Remove(destPath)
		slog.Warn("save received file: write failed", "path", destPath, "err", err)
		return fmt.Errorf("write: %w", err)
	}
	slog.Info("file saved", "path", destPath, "bytes", len(frame.Payload))
	if s.deps.Events != nil {
		s.deps.Events.Publish("file.received", map[string]any{
			"filename": safeName, "size": len(frame.Payload), "path": destPath,
		})
	}
	return nil
}

func (s *Service) saveInboxMessage(frame *internaldx.Frame, from protocol.Addr) error {
	dir, err := s.inboxDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	ts := time.Now()
	msg := map[string]interface{}{
		"type":        internaldx.TypeName(frame.Type),
		"from":        from.String(),
		"data":        string(frame.Payload),
		"bytes":       len(frame.Payload),
		"received_at": ts.Format(time.RFC3339Nano),
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	seq := s.seq.Add(1)
	filename := fmt.Sprintf("%s-%s-%06d.json", internaldx.TypeName(frame.Type), ts.Format("20060102-150405.000"), seq)
	destPath := filepath.Join(dir, filename)
	if err := os.WriteFile(destPath, data, 0600); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	slog.Info("inbox message saved", "path", destPath, "type", internaldx.TypeName(frame.Type), "bytes", len(frame.Payload))
	if s.deps.Events != nil {
		s.deps.Events.Publish("message.received", map[string]any{
			"type": internaldx.TypeName(frame.Type), "from": from.String(),
			"size": len(frame.Payload),
		})
	}
	return nil
}
