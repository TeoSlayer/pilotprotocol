package tasksubmit

import (
	"log/slog"
	"net"

	"web4/pkg/driver"
	"web4/pkg/protocol"
)

// Handler is called for each incoming task submission request.
// It should return true to accept the task, false to reject it.
type Handler func(conn net.Conn, req *SubmitRequest) bool

// ResultSender is a callback for sending task results back to the submitter.
type ResultSender func(result *TaskResult) error

// Server listens on port 1003 and dispatches incoming task submissions to a handler.
type Server struct {
	driver   *driver.Driver
	listener *driver.Listener
	handler  Handler
}

// NewServer creates a task submission server.
func NewServer(d *driver.Driver, handler Handler) *Server {
	return &Server{driver: d, handler: handler}
}

// ListenAndServe binds port 1003 and starts accepting connections.
func (s *Server) ListenAndServe() error {
	ln, err := s.driver.Listen(protocol.PortTaskSubmit)
	if err != nil {
		return err
	}
	s.listener = ln

	slog.Info("tasksubmit listening", "port", protocol.PortTaskSubmit)

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	// Read task submission request
	frame, err := ReadFrame(conn)
	if err != nil {
		slog.Warn("tasksubmit: failed to read frame", "error", err)
		return
	}

	if frame.Type != TypeSubmit {
		slog.Warn("tasksubmit: unexpected frame type", "type", frame.Type)
		return
	}

	req, err := UnmarshalSubmitRequest(frame)
	if err != nil {
		slog.Warn("tasksubmit: failed to unmarshal request", "error", err)
		return
	}

	slog.Debug("tasksubmit: received task",
		"description", req.TaskDescription,
		"remote", conn.RemoteAddr(),
	)

	// Call handler to decide accept/reject
	accepted := s.handler(conn, req)

	var resp *SubmitResponse
	if accepted {
		resp = &SubmitResponse{
			Status:  StatusAccepted,
			Message: "Task accepted and queued",
		}
	} else {
		resp = &SubmitResponse{
			Status:  StatusRejected,
			Message: "Task rejected",
		}
	}

	// Send response
	respFrame, err := MarshalSubmitResponse(resp)
	if err != nil {
		slog.Warn("tasksubmit: failed to marshal response", "error", err)
		return
	}

	if err := WriteFrame(conn, respFrame); err != nil {
		slog.Warn("tasksubmit: failed to write response", "error", err)
		return
	}

	slog.Info("tasksubmit: response sent",
		"status", resp.Status,
		"accepted", accepted,
		"remote", conn.RemoteAddr(),
	)
}
