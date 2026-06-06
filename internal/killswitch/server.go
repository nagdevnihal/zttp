// internal/killswitch/server.go
package killswitch

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/google/uuid"
	pb "github.com/nagdevnihal/zttp/internal/killswitch/proto"
	"github.com/nagdevnihal/zttp/internal/session"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type KillSwitchServer struct {
	pb.UnimplementedKillSwitchServiceServer
	manager      *ConnectionManager
	sessionStore *session.Store
	logger       *zap.Logger
}

func NewKillSwitchServer(manager *ConnectionManager, sessionStore *session.Store, logger *zap.Logger) *KillSwitchServer {
	return &KillSwitchServer{
		manager:      manager,
		sessionStore: sessionStore,
		logger:       logger,
	}
}

// TerminateSession implements the gRPC RPC.
func (s *KillSwitchServer) TerminateSession(ctx context.Context, req *pb.TerminateRequest) (*pb.TerminateResponse, error) {
	sessionID, err := uuid.Parse(req.SessionId)
	if err != nil {
		return &pb.TerminateResponse{Success: false, ErrorMessage: "invalid session_id"}, nil
	}

	elapsed, err := s.manager.Terminate(sessionID, req.Reason)
	if err != nil {
		return &pb.TerminateResponse{
			Success:      false,
			ErrorMessage: err.Error(),
		}, nil
	}

	// Update DB status to terminated-kill
	_ = s.sessionStore.Terminate(ctx, sessionID, session.StatusTerminatedKill)

	return &pb.TerminateResponse{
		Success:   true,
		ElapsedMs: elapsed,
	}, nil
}

// ListActiveSessions returns all sessions currently tracked by this node.
func (s *KillSwitchServer) ListActiveSessions(ctx context.Context, _ *pb.ListRequest) (*pb.ListResponse, error) {
	myIP := os.Getenv("PROXY_NODE_IP")
	if myIP == "" {
		myIP = "127.0.0.1" // fallback
	}

	sessions, err := s.sessionStore.GetActiveByProxyNode(ctx, myIP)
	if err != nil {
		return nil, err
	}
	var pbSessions []*pb.SessionInfo
	for _, sess := range sessions {
		pbSessions = append(pbSessions, &pb.SessionInfo{
			SessionId:   sess.SessionID.String(),
			UserId:      sess.UserID.String(),
			ServerId:    sess.ServerID.String(),
			ProxyNodeIp: sess.ProxyNodeIP.String(),
			StartTime:   sess.StartTime.Unix(),
		})
	}
	return &pb.ListResponse{Sessions: pbSessions}, nil
}

// StartGRPCServer starts the gRPC listener on the configured port.
func StartGRPCServer(addr string, ks *KillSwitchServer, certFile, keyFile string) error {
	creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("grpc tls: %w", err)
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("grpc listen: %w", err)
	}

	srv := grpc.NewServer(grpc.Creds(creds))
	pb.RegisterKillSwitchServiceServer(srv, ks)
	return srv.Serve(ln)
}
