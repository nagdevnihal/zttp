package proxy

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/google/uuid"
)

type gatewayServerOption struct {
	hostname    string
	environment string
}

func (s *Server) handleGatewayMenu(ctx context.Context, conn net.Conn, userID uuid.UUID, role string) (string, error) {
	opts, err := s.queryAccessibleServers(userID, role)
	if err != nil {
		s.drawGatewayError(conn, err)
		s.readKey(conn)
		return "", err
	}

	index := 0
	for {
		s.drawGatewayMenu(conn, opts, index)

		key, err := s.readKey(conn)
		if err != nil {
			return "", err
		}

		if key == "CTRL_C" || key == "ESC" {
			s.clearScreen(conn)
			return "", fmt.Errorf("user aborted")
		}

		switch key {
		case "UP":
			if index > 0 {
				index--
			}
		case "DOWN":
			if index < len(opts) {
				index++
			}
		case "ENTER":
			if index == len(opts) {
				s.clearScreen(conn)
				return "", fmt.Errorf("user exited gateway")
			}
			s.clearScreen(conn)
			return opts[index].hostname, nil
		}
	}
}

func (s *Server) queryAccessibleServers(userID uuid.UUID, role string) ([]gatewayServerOption, error) {
	var opts []gatewayServerOption

	if role == "security-admin" {
		opts = append(opts, gatewayServerOption{
			hostname:    "zttp-admin",
			environment: "system",
		})
	}

	query := `
		SELECT s.hostname, s.environment
		FROM servers s
		CROSS JOIN users u
		LEFT JOIN policies p ON p.role = u.role
		LEFT JOIN user_server_grants g ON g.server_id = s.id AND g.user_id = $1
		WHERE u.id = $1
		  AND (g.user_id IS NOT NULL OR (u.override_role_access = false AND s.environment = ANY(p.allowed_environments)))
		ORDER BY s.hostname
	`
	rows, err := s.DB.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var opt gatewayServerOption
		if err := rows.Scan(&opt.hostname, &opt.environment); err == nil {
			opts = append(opts, opt)
		}
	}
	return opts, nil
}

func (s *Server) drawGatewayMenu(conn net.Conn, opts []gatewayServerOption, index int) {
	s.clearScreen(conn)
	var out strings.Builder
	out.WriteString(fmt.Sprintf("%s=== ZTTP Server Gateway ===%s\r\n", ColorCyan, ColorReset))
	out.WriteString("Select a server to connect to (UP/DOWN, ENTER to select):\r\n\r\n")

	if len(opts) == 0 {
		out.WriteString("  No servers available for your role.\r\n")
	}

	for i, opt := range opts {
		if i == index {
			out.WriteString(fmt.Sprintf("%s> %-15s (%s)%s\r\n", ColorGreen, opt.hostname, opt.environment, ColorReset))
		} else {
			out.WriteString(fmt.Sprintf("  %-15s (%s)\r\n", opt.hostname, opt.environment))
		}
		
		if opt.hostname == "zttp-admin" {
			out.WriteString("  ────────────────────────────────────────\r\n")
		}
	}

	out.WriteString("\r\n")
	if index == len(opts) {
		out.WriteString(fmt.Sprintf("%s> [ Logout ]%s\r\n", ColorRed, ColorReset))
	} else {
		out.WriteString("  [ Logout ]\r\n")
	}

	conn.Write([]byte(out.String()))
}

func (s *Server) drawGatewayError(conn net.Conn, err error) {
	s.clearScreen(conn)
	conn.Write([]byte(fmt.Sprintf("%sError loading servers: %v%s\r\n\r\nPress any key to exit...", ColorRed, err, ColorReset)))
}
