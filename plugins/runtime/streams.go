// SPDX-License-Identifier: AGPL-3.0-or-later

package runtime

import (
	"context"
	"errors"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/coreapi"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
)

// daemonStreams is the in-process implementation of coreapi.Streams.
// Lives here (plugins/runtime) so daemon doesn't carry the L10 import.

type daemonStreams struct{ d *daemon.Daemon }

func (s daemonStreams) Listen(port uint16) (coreapi.Listener, error) {
	ln, err := s.d.Ports().Bind(port)
	if err != nil {
		return nil, err
	}
	return &daemonListener{inner: ln, d: s.d}, nil
}

func (s daemonStreams) Dial(ctx context.Context, dst coreapi.Addr, port uint16) (coreapi.Stream, error) {
	conn, err := s.d.DialConnectionContext(ctx, dst, port)
	if err != nil {
		return nil, err
	}
	return newStreamAdapter(s.d, conn), nil
}

func (s daemonStreams) SendDatagram(ctx context.Context, dst coreapi.Addr, port uint16, data []byte) error {
	return s.d.SendDatagram(dst, port, data)
}

type daemonListener struct {
	inner *daemon.Listener
	d     *daemon.Daemon
}

func (l *daemonListener) Accept() (coreapi.Stream, error) {
	conn, ok := <-l.inner.AcceptCh
	if !ok {
		return nil, errors.New("listener closed")
	}
	return newStreamAdapter(l.d, conn), nil
}

func (l *daemonListener) Close() error {
	l.d.Ports().Unbind(l.inner.Port)
	return nil
}

func (l *daemonListener) Addr() coreapi.Addr { return l.d.Addr() }
func (l *daemonListener) Port() uint16       { return l.inner.Port }

// streamAdapter wraps *daemon.Connection so it satisfies coreapi.Stream.
// Daemon exposes a connAdapter via Daemon.NewConnAdapter for this.
type streamAdapter struct {
	d    *daemon.Daemon
	conn *daemon.Connection
	rw   daemon.ConnReadWriter
}

func newStreamAdapter(d *daemon.Daemon, conn *daemon.Connection) *streamAdapter {
	return &streamAdapter{d: d, conn: conn, rw: d.NewConnReadWriter(conn)}
}

func (s *streamAdapter) Read(p []byte) (int, error)  { return s.rw.Read(p) }
func (s *streamAdapter) Write(p []byte) (int, error) { return s.rw.Write(p) }
func (s *streamAdapter) Close() error                { return s.rw.Close() }

func (s *streamAdapter) LocalAddr() coreapi.Addr  { return s.conn.LocalAddr }
func (s *streamAdapter) LocalPort() uint16        { return s.conn.LocalPort }
func (s *streamAdapter) RemoteAddr() coreapi.Addr { return s.conn.RemoteAddr }
func (s *streamAdapter) RemotePort() uint16       { return s.conn.RemotePort }

func (s *streamAdapter) SetDeadline(time.Time) error      { return nil }
func (s *streamAdapter) SetReadDeadline(time.Time) error  { return nil }
func (s *streamAdapter) SetWriteDeadline(time.Time) error { return nil }

var (
	_ coreapi.Streams  = daemonStreams{}
	_ coreapi.Listener = (*daemonListener)(nil)
	_ coreapi.Stream   = (*streamAdapter)(nil)
)
