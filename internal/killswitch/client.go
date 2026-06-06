// internal/killswitch/client.go
package killswitch

import (
	"context"
	"fmt"
	"time"

	pb "github.com/nagdevnihal/zttp/internal/killswitch/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// KillSwitchClient routes a termination command to the correct proxy node.
type KillSwitchClient struct {
	caFile string // TLS CA cert for verifying proxy nodes
}

func NewKillSwitchClient(caFile string) *KillSwitchClient {
	return &KillSwitchClient{caFile: caFile}
}

// TerminateSession dials the proxy node hosting the session and fires the kill signal.
func (c *KillSwitchClient) TerminateSession(proxyNodeIP, sessionID, reason string) error {
	addr := fmt.Sprintf("%s:9090", proxyNodeIP)

	// Note: in a real deployment, we'd use a shared CA cert. For dev testing, we'll
	// just load the self-signed cert if CA is not provided, or disable verify.
	var creds credentials.TransportCredentials
	var err error
	if c.caFile != "" {
		creds, err = credentials.NewClientTLSFromFile(c.caFile, "")
		if err != nil {
			return fmt.Errorf("grpc client tls: %w", err)
		}
	} else {
		return fmt.Errorf("caFile is required for KillSwitchClient")
	}

	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return fmt.Errorf("grpc dial %s: %w", addr, err)
	}
	defer conn.Close()

	client := pb.NewKillSwitchServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := client.TerminateSession(ctx, &pb.TerminateRequest{
		SessionId: sessionID,
		Reason:    reason,
	})
	if err != nil {
		return fmt.Errorf("grpc call: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("termination failed: %s", resp.ErrorMessage)
	}
	return nil
}
