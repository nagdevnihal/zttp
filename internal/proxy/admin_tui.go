package proxy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

type adminState int

const (
	StateMainMenu adminState = iota
	StateAddUser
	StateRoleSelect
	StateSelectUserForAssign
	StateAssignAccess
	StateViewUsers
	StateViewServers
	StateSummary
	StateAddServer
	StateAddServerMethod
	StateAddServerAuto
	StateAddServerPaste
)

const (
	ColorReset = "\033[0m"
	ColorCyan  = "\033[36m"
	ColorGreen = "\033[32m"
	ColorRed   = "\033[31m"
	ColorBold  = "\033[1m"
)

type addUserForm struct {
	username string
	password string
	confirm  string
	role     string
	focus    int // 0: user, 1: pass, 2: conf, 3: submit
}

type addServerForm struct {
	hostname    string
	ip          string
	environment string
	sshUser     string
	focus       int // 0: host, 1: ip, 2: env, 3: sshUser, 4: submit
}

type addServerAutoForm struct {
	username string
	password string
	focus    int // 0: user, 1: pass, 2: submit
}

type serverOption struct {
	id          string
	hostname    string
	environment string
	selected    bool
}

func (s *Server) handleAdminConsole(ctx context.Context, conn net.Conn, adminUsername string) {
	state := StateMainMenu
	menuIndex := 0

	uForm := &addUserForm{}
	sForm := &addServerForm{}
	autoForm := &addServerAutoForm{}
	pasteBuffer := ""
	
	var createdUserMsg string
	var createdUserID string
	var isEditMode bool
	
	var roles []string
	var serverOpts []serverOption

	for {
		s.clearScreen(conn)

		switch state {
		case StateMainMenu:
			s.drawMainMenu(conn, adminUsername, menuIndex)
		case StateAddUser:
			s.drawAddUserForm(conn, uForm)
		case StateAddServer:
			s.drawAddServerForm(conn, sForm)
		case StateAddServerMethod:
			s.drawAddServerMethod(conn, menuIndex)
		case StateAddServerAuto:
			s.drawAddServerAuto(conn, autoForm)
		case StateAddServerPaste:
			s.drawAddServerPaste(conn, pasteBuffer)
		case StateRoleSelect:
			s.drawRoleSelect(conn, roles, menuIndex)
		case StateSelectUserForAssign:
			s.drawSelectUserForAssign(conn, menuIndex)
		case StateAssignAccess:
			s.drawAssignAccess(conn, uForm.username, serverOpts, menuIndex, isEditMode)
		case StateSummary:
			s.drawSummary(conn, uForm.username, uForm.password, uForm.role, createdUserMsg, serverOpts)
		case StateViewUsers:
			s.drawViewUsers(conn)
		case StateViewServers:
			s.drawViewServers(conn)
		}

		key, err := s.readKey(conn)
		if err != nil {
			return
		}
		if key == "CTRL_C" {
			return
		}

		switch state {
		case StateMainMenu:
			switch key {
			case "UP":
				if menuIndex > 0 {
					menuIndex--
				}
			case "DOWN":
				if menuIndex < 5 {
					menuIndex++
				}
			case "ENTER":
				switch menuIndex {
				case 0:
					state = StateAddUser
					uForm = &addUserForm{}
					isEditMode = false
				case 1:
					state = StateAddServer
					sForm = &addServerForm{}
				case 2:
					state = StateSelectUserForAssign
					menuIndex = 0
				case 3:
					state = StateViewUsers
				case 4:
					state = StateViewServers
				case 5:
					return // Back to gateway menu
				}
				menuIndex = 0
			}

		case StateAddServer:
			switch key {
			case "UP":
				if sForm.focus > 0 {
					sForm.focus--
				}
			case "DOWN":
				if sForm.focus < 5 {
					sForm.focus++
				}
			case "ENTER":
				if sForm.focus == 4 {
					if sForm.hostname == "" || sForm.ip == "" || sForm.environment == "" || sForm.sshUser == "" {
						break
					}
					state = StateAddServerMethod
					menuIndex = 0
				} else if sForm.focus == 5 {
					state = StateMainMenu
					menuIndex = 0
				} else {
					sForm.focus++
				}
			case "BACKSPACE":
				if sForm.focus == 0 && len(sForm.hostname) > 0 {
					sForm.hostname = sForm.hostname[:len(sForm.hostname)-1]
				} else if sForm.focus == 1 && len(sForm.ip) > 0 {
					sForm.ip = sForm.ip[:len(sForm.ip)-1]
				} else if sForm.focus == 2 && len(sForm.environment) > 0 {
					sForm.environment = sForm.environment[:len(sForm.environment)-1]
				} else if sForm.focus == 3 && len(sForm.sshUser) > 0 {
					sForm.sshUser = sForm.sshUser[:len(sForm.sshUser)-1]
				}
			default:
				if len(key) == 1 && key != " " && key != "\t" {
					if sForm.focus == 0 {
						sForm.hostname += key
					} else if sForm.focus == 1 {
						sForm.ip += key
					} else if sForm.focus == 2 {
						sForm.environment += key
					} else if sForm.focus == 3 {
						sForm.sshUser += key
					}
				}
			}

		case StateAddServerMethod:
			switch key {
			case "UP":
				if menuIndex > 0 {
					menuIndex--
				}
			case "DOWN":
				if menuIndex < 3 {
					menuIndex++
				}
			case "ENTER":
				switch menuIndex {
				case 0: // Auto-Install
					state = StateAddServerAuto
					autoForm = &addServerAutoForm{}
				case 1: // Paste Key
					state = StateAddServerPaste
					pasteBuffer = ""
				case 2: // Manual
					pubKey, _, err := s.generateAndSaveServer(ctx, sForm.hostname, sForm.ip, sForm.environment, sForm.sshUser)
					if err != nil {
						createdUserMsg = fmt.Sprintf("Error creating server: %v", err)
					} else {
						createdUserMsg = fmt.Sprintf("Server '%s' created!\r\n\r\nPlease manually install this Public Key on the server:\r\n%s", sForm.hostname, pubKey)
					}
					uForm = &addUserForm{}
					serverOpts = nil
					state = StateSummary
					menuIndex = 0
				case 3: // Back
					state = StateMainMenu
					menuIndex = 0
				}
			}

		case StateAddServerAuto:
			switch key {
			case "UP":
				if autoForm.focus > 0 {
					autoForm.focus--
				}
			case "DOWN":
				if autoForm.focus < 3 {
					autoForm.focus++
				}
			case "ENTER":
				if autoForm.focus == 2 {
					if autoForm.username == "" || autoForm.password == "" {
						break
					}
					pubKey, _, err := s.generateAndSaveServer(ctx, sForm.hostname, sForm.ip, sForm.environment, sForm.sshUser)
					if err != nil {
						createdUserMsg = fmt.Sprintf("Error creating server: %v", err)
					} else {
						err = s.autoProvisionKey(sForm.ip, autoForm.username, autoForm.password, pubKey)
						if err != nil {
							createdUserMsg = fmt.Sprintf("Server saved, but auto-provisioning failed: %v\r\n\r\nPlease manually install this Public Key:\r\n%s", err, pubKey)
						} else {
							createdUserMsg = fmt.Sprintf("Server '%s' successfully Auto-Provisioned!", sForm.hostname)
						}
					}
					uForm = &addUserForm{}
					serverOpts = nil
					state = StateSummary
					menuIndex = 0
				} else if autoForm.focus == 3 {
					state = StateMainMenu
					menuIndex = 0
				} else {
					autoForm.focus++
				}
			case "BACKSPACE":
				if autoForm.focus == 0 && len(autoForm.username) > 0 {
					autoForm.username = autoForm.username[:len(autoForm.username)-1]
				} else if autoForm.focus == 1 && len(autoForm.password) > 0 {
					autoForm.password = autoForm.password[:len(autoForm.password)-1]
				}
			default:
				if len(key) == 1 && key != " " && key != "\t" {
					if autoForm.focus == 0 {
						autoForm.username += key
					} else if autoForm.focus == 1 {
						autoForm.password += key
					}
				}
			}

		case StateAddServerPaste:
			switch key {
			case "CTRL_S":
				if len(pasteBuffer) < 50 {
					break // basic validation to prevent empty submission
				}
				err := s.saveCustomServer(ctx, sForm.hostname, sForm.ip, sForm.environment, sForm.sshUser, pasteBuffer)
				if err != nil {
					createdUserMsg = fmt.Sprintf("Error creating server with custom key: %v", err)
				} else {
					createdUserMsg = fmt.Sprintf("Server '%s' created securely using provided Private Key!", sForm.hostname)
				}
				uForm = &addUserForm{}
				serverOpts = nil
				state = StateSummary
				menuIndex = 0
			case "ENTER":
				pasteBuffer += "\r\n"
			case "BACKSPACE":
				if len(pasteBuffer) > 0 {
					pasteBuffer = pasteBuffer[:len(pasteBuffer)-1]
				}
			default:
				if len(key) == 1 {
					pasteBuffer += key
				}
			}

		case StateAddUser:
			switch key {
			case "UP":
				if uForm.focus > 0 {
					uForm.focus--
				}
			case "DOWN":
				if uForm.focus < 4 {
					uForm.focus++
				}
			case "ENTER":
				if uForm.focus == 3 {
					if uForm.username == "" || uForm.password == "" || uForm.password != uForm.confirm {
						break
					}
					roles = s.queryRoles()
					menuIndex = 0
					state = StateRoleSelect
				} else if uForm.focus == 4 {
					state = StateMainMenu
					menuIndex = 0
				} else {
					uForm.focus++
				}
			case "BACKSPACE":
				if uForm.focus == 0 && len(uForm.username) > 0 {
					uForm.username = uForm.username[:len(uForm.username)-1]
				} else if uForm.focus == 1 && len(uForm.password) > 0 {
					uForm.password = uForm.password[:len(uForm.password)-1]
				} else if uForm.focus == 2 && len(uForm.confirm) > 0 {
					uForm.confirm = uForm.confirm[:len(uForm.confirm)-1]
				}
			default:
				if len(key) == 1 && key != " " && key != "\t" {
					if uForm.focus == 0 {
						uForm.username += key
					} else if uForm.focus == 1 {
						uForm.password += key
					} else if uForm.focus == 2 {
						uForm.confirm += key
					}
				}
			}

		case StateRoleSelect:
			switch key {
			case "UP":
				if menuIndex > 0 {
					menuIndex--
				}
			case "DOWN":
				if menuIndex < len(roles)-1 {
					menuIndex++
				}
			case "ENTER":
				uForm.role = roles[menuIndex]
				id, err := s.createUser(uForm.username, uForm.password, uForm.role)
				if err != nil {
					createdUserMsg = fmt.Sprintf("Error creating user: %v", err)
					state = StateSummary
				} else {
					createdUserMsg = fmt.Sprintf("User '%s' created successfully!", uForm.username)
					createdUserID = id
					serverOpts = s.queryServers()
					state = StateAssignAccess
				}
				menuIndex = 0
			}

		case StateAssignAccess:
			maxIdx := len(serverOpts) + 1
			switch key {
			case "UP":
				if menuIndex > 0 {
					menuIndex--
				}
			case "DOWN":
				if menuIndex < maxIdx {
					menuIndex++
				}
			case "ENTER":
				if menuIndex < len(serverOpts) {
					serverOpts[menuIndex].selected = !serverOpts[menuIndex].selected
				} else if menuIndex == len(serverOpts) {
					revoked, err := s.assignServers(createdUserID, serverOpts)
					if err != nil {
						createdUserMsg = fmt.Sprintf("Error managing access: %v", err)
					} else {
						msg := "Access successfully updated!"
						if len(revoked) > 0 {
							msg += fmt.Sprintf("\r\n\r\nRevoked access to: %s\r\nActive sessions for these servers were instantly killed.", strings.Join(revoked, ", "))
						}
						createdUserMsg = msg
					}
					state = StateSummary
					menuIndex = 0
				} else {
					for i := range serverOpts {
						serverOpts[i].selected = false
					}
					state = StateSummary
					menuIndex = 0
				}
			}

		case StateSummary:
			if key == "ENTER" {
				state = StateMainMenu
				menuIndex = 0
			}

		case StateViewUsers, StateViewServers:
			if key == "ENTER" {
				state = StateMainMenu
				menuIndex = 0
			}

		case StateSelectUserForAssign:
			var users []string
			rows, err := s.DB.Query("SELECT id, username, role FROM users ORDER BY username")
			if err == nil {
				for rows.Next() {
					var id, user, role string
					rows.Scan(&id, &user, &role)
					users = append(users, fmt.Sprintf("%s|%s|%s", id, user, role))
				}
				rows.Close()
			}
			maxIdx := len(users)

			switch key {
			case "UP":
				if menuIndex > 0 {
					menuIndex--
				}
			case "DOWN":
				if menuIndex < maxIdx {
					menuIndex++
				}
			case "ENTER":
				if menuIndex == maxIdx { // Back
					state = StateMainMenu
					menuIndex = 0
				} else if menuIndex < len(users) {
					parts := strings.Split(users[menuIndex], "|")
					createdUserID = parts[0]
					uForm.username = parts[1]
					uForm.role = parts[2]
					
					// Populate serverOpts
					serverOpts = nil
					sRows, err := s.DB.Query("SELECT id, hostname, environment FROM servers ORDER BY hostname")
					if err == nil {
						for sRows.Next() {
							var sID, hostname, env string
							sRows.Scan(&sID, &hostname, &env)
							
							// Check if currently assigned
							var exists bool
							s.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM user_server_grants WHERE user_id = $1 AND server_id = $2)", createdUserID, sID).Scan(&exists)
							
							serverOpts = append(serverOpts, serverOption{
								id:          sID,
								hostname:    hostname,
								environment: env,
								selected:    exists,
							})
						}
						sRows.Close()
					}
					
					isEditMode = true
					state = StateAssignAccess
					menuIndex = 0
				}
			}
		}
	}
}

func (s *Server) clearScreen(conn net.Conn) {
	conn.Write([]byte("\033[2J\033[H"))
}

func (s *Server) drawMainMenu(conn net.Conn, adminUsername string, index int) {
	opts := []string{"Add User", "Add Server", "Manage Server Access", "View Users", "View Servers", "Back to Servers"}
	var out strings.Builder
	out.WriteString(fmt.Sprintf("%s=== ZTTP Admin Console ===%s\r\n", ColorCyan, ColorReset))
	out.WriteString(fmt.Sprintf("Logged in as: %s\r\n\r\n", adminUsername))

	for i, opt := range opts {
		if i == index {
			out.WriteString(fmt.Sprintf("%s> %s%s\r\n", ColorGreen, opt, ColorReset))
		} else {
			out.WriteString(fmt.Sprintf("  %s\r\n", opt))
		}
	}
	conn.Write([]byte(out.String()))
}

func (s *Server) drawAddUserForm(conn net.Conn, form *addUserForm) {
	var out strings.Builder
	out.WriteString(fmt.Sprintf("%s=== Create New User ===%s\r\n\r\n", ColorCyan, ColorReset))

	drawField(&out, "Username", form.username, false, form.focus == 0)
	drawField(&out, "Password", form.password, true, form.focus == 1)
	drawField(&out, "Confirm ", form.confirm, true, form.focus == 2)

	out.WriteString("\r\n")
	if form.focus == 3 {
		out.WriteString(fmt.Sprintf("%s> [ Confirm ]%s\r\n", ColorGreen, ColorReset))
	} else {
		out.WriteString("  [ Confirm ]\r\n")
	}

	if form.focus == 4 {
		out.WriteString(fmt.Sprintf("%s> [ Back ]%s\r\n", ColorRed, ColorReset))
	} else {
		out.WriteString("  [ Back ]\r\n")
	}

	if form.password != form.confirm && len(form.confirm) > 0 {
		out.WriteString(fmt.Sprintf("\r\n%s* Passwords do not match%s\r\n", ColorRed, ColorReset))
	}
	conn.Write([]byte(out.String()))
}

func (s *Server) drawAddServerForm(conn net.Conn, form *addServerForm) {
	var out strings.Builder
	out.WriteString(fmt.Sprintf("%s=== Add New Server ===%s\r\n", ColorCyan, ColorReset))
	out.WriteString("Step 1: Server Details\r\n\r\n")

	drawField(&out, "Hostname   ", form.hostname, false, form.focus == 0)
	drawField(&out, "Private IP ", form.ip, false, form.focus == 1)
	drawField(&out, "Environment", form.environment, false, form.focus == 2)
	drawField(&out, "Target User", form.sshUser, false, form.focus == 3)

	out.WriteString("\r\n")
	if form.focus == 4 {
		out.WriteString(fmt.Sprintf("%s> [ Next ]%s\r\n", ColorGreen, ColorReset))
	} else {
		out.WriteString("  [ Next ]\r\n")
	}

	if form.focus == 5 {
		out.WriteString(fmt.Sprintf("%s> [ Back ]%s\r\n", ColorRed, ColorReset))
	} else {
		out.WriteString("  [ Back ]\r\n")
	}
	conn.Write([]byte(out.String()))
}

func (s *Server) drawAddServerMethod(conn net.Conn, index int) {
	opts := []string{
		"Auto-Install (Provide SSH Password)",
		"Paste Existing Private Key",
		"Manual (I will copy the public key myself)",
		"Back",
	}
	var out strings.Builder
	out.WriteString(fmt.Sprintf("%s=== Add New Server ===%s\r\n", ColorCyan, ColorReset))
	out.WriteString("Step 2: Key Provisioning Method\r\n\r\n")

	for i, opt := range opts {
		if i == index {
			out.WriteString(fmt.Sprintf("%s> %s%s\r\n", ColorGreen, opt, ColorReset))
		} else {
			out.WriteString(fmt.Sprintf("  %s\r\n", opt))
		}
	}
	conn.Write([]byte(out.String()))
}

func (s *Server) drawAddServerAuto(conn net.Conn, form *addServerAutoForm) {
	var out strings.Builder
	out.WriteString(fmt.Sprintf("%s=== Auto-Install SSH Key ===%s\r\n", ColorCyan, ColorReset))
	out.WriteString("ZTTP will temporarily log in using this password to inject the new key.\r\n")
	out.WriteString("The password will NOT be saved.\r\n\r\n")

	drawField(&out, "SSH Username", form.username, false, form.focus == 0)
	drawField(&out, "SSH Password", form.password, true, form.focus == 1)

	out.WriteString("\r\n")
	if form.focus == 2 {
		out.WriteString(fmt.Sprintf("%s> [ Provision Server ]%s\r\n", ColorGreen, ColorReset))
	} else {
		out.WriteString("  [ Provision Server ]\r\n")
	}

	if form.focus == 3 {
		out.WriteString(fmt.Sprintf("%s> [ Back ]%s\r\n", ColorRed, ColorReset))
	} else {
		out.WriteString("  [ Back ]\r\n")
	}
	conn.Write([]byte(out.String()))
}

func (s *Server) drawAddServerPaste(conn net.Conn, buffer string) {
	var out strings.Builder
	out.WriteString(fmt.Sprintf("%s=== Paste Private Key ===%s\r\n", ColorCyan, ColorReset))
	out.WriteString("Paste your multi-line PEM encoded private key below.\r\n")
	out.WriteString(fmt.Sprintf("When finished, press %sCTRL+S%s to save.\r\n", ColorGreen, ColorReset))
	out.WriteString("--------------------------------------------------\r\n")
	out.WriteString(buffer)
	
	// Print cursor simulation
	out.WriteString("█")
	
	conn.Write([]byte(out.String()))
}

func (s *Server) drawRoleSelect(conn net.Conn, roles []string, index int) {
	var out strings.Builder
	out.WriteString(fmt.Sprintf("%s=== Select Role ===%s\r\n\r\n", ColorCyan, ColorReset))

	for i, r := range roles {
		if i == index {
			out.WriteString(fmt.Sprintf("%s> %s%s\r\n", ColorGreen, r, ColorReset))
		} else {
			out.WriteString(fmt.Sprintf("  %s\r\n", r))
		}
	}
	conn.Write([]byte(out.String()))
}

func (s *Server) drawAssignAccess(conn net.Conn, username string, opts []serverOption, index int, isEditMode bool) {
	var out strings.Builder
	out.WriteString(fmt.Sprintf("%s=== Manage Server Access ===%s\r\n", ColorCyan, ColorReset))
	out.WriteString(fmt.Sprintf("Select servers for user '%s' (UP/DOWN, ENTER to toggle)\r\n\r\n", username))

	for i, opt := range opts {
		prefix := "  "
		if i == index {
			prefix = ColorGreen + "> "
		}
		
		tick := "[ ]"
		if opt.selected {
			tick = "[x]"
		}
		
		out.WriteString(fmt.Sprintf("%s%s %-15s (%s)%s\r\n", prefix, tick, opt.hostname, opt.environment, ColorReset))
	}

	out.WriteString("\r\n")
	
	assignIdx := len(opts)
	skipIdx := len(opts) + 1
	
	if index == assignIdx {
		out.WriteString(fmt.Sprintf("%s> [ Assign ]%s\r\n", ColorGreen, ColorReset))
	} else {
		out.WriteString("  [ Assign ]\r\n")
	}
	
	if index == skipIdx {
		if isEditMode {
			out.WriteString(fmt.Sprintf("%s> [ Back ]%s\r\n", ColorRed, ColorReset))
		} else {
			out.WriteString(fmt.Sprintf("%s> [ Skip for now ]%s\r\n", ColorRed, ColorReset))
		}
	} else {
		if isEditMode {
			out.WriteString("  [ Back ]\r\n")
		} else {
			out.WriteString("  [ Skip for now ]\r\n")
		}
	}

	conn.Write([]byte(out.String()))
}

func (s *Server) drawSummary(conn net.Conn, username, password, role, msg string, servers []serverOption) {
	var out strings.Builder
	out.WriteString(fmt.Sprintf("%s%s%s\r\n\r\n", ColorGreen, msg, ColorReset))
	
	if !strings.HasPrefix(msg, "Error") && username != "" {
		out.WriteString(fmt.Sprintf("%sUser Details:%s\r\n", ColorCyan, ColorReset))
		out.WriteString(fmt.Sprintf("Username: %s\r\n", username))
		out.WriteString(fmt.Sprintf("Role:     %s\r\n\r\n", role))
		
		out.WriteString(fmt.Sprintf("%sAssigned Servers:%s\r\n", ColorCyan, ColorReset))
		assignedCount := 0
		for _, srv := range servers {
			if srv.selected {
				out.WriteString(fmt.Sprintf("- %s (%s)\r\n", srv.hostname, srv.environment))
				assignedCount++
			}
		}
		if assignedCount == 0 {
			out.WriteString("No specific access granted yet.\r\n")
		}
		out.WriteString("\r\n")
	}
	
	out.WriteString("Press ENTER to return to Main Menu...")
	conn.Write([]byte(out.String()))
}

func (s *Server) drawViewUsers(conn net.Conn) {
	var out strings.Builder
	out.WriteString(fmt.Sprintf("%s=== Registered Users ===%s\r\n\r\n", ColorCyan, ColorReset))
	out.WriteString(fmt.Sprintf("%-15s %-15s %-10s\r\n", "USERNAME", "ROLE", "LOCKED"))
	out.WriteString("--------------------------------------------------\r\n")

	rows, err := s.DB.Query("SELECT username, role, locked_until FROM users ORDER BY username")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var username, role string
			var lockedUntil *time.Time
			rows.Scan(&username, &role, &lockedUntil)
			locked := "false"
			if lockedUntil != nil && lockedUntil.After(time.Now()) {
				locked = "true"
			}
			out.WriteString(fmt.Sprintf("%-15s %-15s %-10s\r\n", username, role, locked))
		}
	} else {
		out.WriteString(fmt.Sprintf("%sError querying users: %v%s\r\n", ColorRed, err, ColorReset))
	}

	out.WriteString("\r\n[ Press ENTER to go back ]")
	conn.Write([]byte(out.String()))
}

func (s *Server) drawViewServers(conn net.Conn) {
	s.clearScreen(conn)
	var out strings.Builder
	out.WriteString(fmt.Sprintf("%s=== Registered Servers ===%s\r\n\r\n", ColorCyan, ColorReset))
	out.WriteString(fmt.Sprintf("%-20s %-15s %-15s %-15s\r\n", "HOSTNAME", "IP", "ENVIRONMENT", "TARGET USER"))
	out.WriteString("----------------------------------------------------------------------\r\n")

	rows, err := s.DB.Query("SELECT hostname, private_ip, environment, ssh_user FROM servers ORDER BY hostname")
	if err == nil {
		defer rows.Close()
		count := 0
		for rows.Next() {
			var hostname, ip, env, sshUser string
			if err := rows.Scan(&hostname, &ip, &env, &sshUser); err == nil {
				out.WriteString(fmt.Sprintf("%-20s %-15s %-15s %-15s\r\n", hostname, ip, env, sshUser))
				count++
			}
		}
		if count == 0 {
			out.WriteString("No servers found.\r\n")
		}
	} else {
		out.WriteString(fmt.Sprintf("%sError querying servers: %v%s\r\n", ColorRed, err, ColorReset))
	}

	out.WriteString(fmt.Sprintf("\r\n%s[ Press ENTER to go back ]%s\r\n", ColorGreen, ColorReset))
	conn.Write([]byte(out.String()))
}

func (s *Server) drawSelectUserForAssign(conn net.Conn, index int) {
	s.clearScreen(conn)
	var out strings.Builder
	out.WriteString(fmt.Sprintf("%s=== Select User to Manage Access ===%s\r\n\r\n", ColorCyan, ColorReset))

	// Fetch users if we haven't already
	var users []string
	rows, err := s.DB.Query("SELECT id, username FROM users ORDER BY username")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var id, user string
			rows.Scan(&id, &user)
			users = append(users, fmt.Sprintf("%s|%s", id, user))
		}
	}

	if len(users) == 0 {
		out.WriteString("No users found.\r\n")
	}

	for i, u := range users {
		parts := strings.Split(u, "|")
		username := parts[1]
		if i == index {
			out.WriteString(fmt.Sprintf("%s> %s%s\r\n", ColorGreen, username, ColorReset))
		} else {
			out.WriteString(fmt.Sprintf("  %s\r\n", username))
		}
	}

	out.WriteString("\r\n")
	if index == len(users) {
		out.WriteString(fmt.Sprintf("%s> [ Back ]%s\r\n", ColorRed, ColorReset))
	} else {
		out.WriteString("  [ Back ]\r\n")
	}
	conn.Write([]byte(out.String()))
}


func drawField(out *strings.Builder, label, val string, hidden, focused bool) {
	displayVal := val
	if hidden {
		displayVal = strings.Repeat("*", len(val))
	}
	
	if focused {
		out.WriteString(fmt.Sprintf("%s> %-11s: %s█%s\r\n", ColorGreen, label, displayVal, ColorReset))
	} else {
		out.WriteString(fmt.Sprintf("  %-11s: %s\r\n", label, displayVal))
	}
}

func (s *Server) queryRoles() []string {
	roles := []string{"unassigned"}
	_, err := s.DB.Exec("INSERT INTO policies (role, allowed_environments) VALUES ('unassigned', ARRAY[]::varchar[]) ON CONFLICT DO NOTHING")
	if err != nil {
		s.Logger.Error("Failed to ensure unassigned policy", zap.Error(err))
	}

	rows, err := s.DB.Query("SELECT role FROM policies ORDER BY role")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var r string
			rows.Scan(&r)
			if r != "unassigned" {
				roles = append(roles, r)
			}
		}
	}
	return roles
}

func (s *Server) queryServers() []serverOption {
	var opts []serverOption
	rows, err := s.DB.Query("SELECT id::text, hostname, environment FROM servers ORDER BY hostname")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var opt serverOption
			rows.Scan(&opt.id, &opt.hostname, &opt.environment)
			opts = append(opts, opt)
		}
	}
	return opts
}

func (s *Server) createUser(username, password, role string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return "", err
	}
	
	var id string
	err = s.DB.QueryRow("INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id::text", username, string(hash), role).Scan(&id)
	return id, err
}

func (s *Server) assignServers(userID string, servers []serverOption) ([]string, error) {
	var revoked []string
	for _, srv := range servers {
		if srv.selected {
			_, err := s.DB.Exec("INSERT INTO user_server_grants (user_id, server_id) VALUES ($1, $2) ON CONFLICT DO NOTHING", userID, srv.id)
			if err != nil {
				return nil, err
			}
		} else {
			res, err := s.DB.Exec("DELETE FROM user_server_grants WHERE user_id = $1 AND server_id = $2", userID, srv.id)
			if err != nil {
				return nil, err
			}
			rowsAffected, _ := res.RowsAffected()
			if rowsAffected > 0 {
				revoked = append(revoked, srv.hostname)
				
				// Kill any active sessions for this user+server
				sessionRows, err := s.DB.Query("SELECT session_id FROM active_sessions WHERE user_id = $1 AND server_id = $2 AND status = 'active'", userID, srv.id)
				if err == nil {
					for sessionRows.Next() {
						var sessionIDStr string
						if err := sessionRows.Scan(&sessionIDStr); err == nil {
							if sessUUID, err := uuid.Parse(sessionIDStr); err == nil {
								s.ConnManager.Terminate(sessUUID, "access revoked")
							}
						}
					}
					sessionRows.Close()
				}
			}
		}
	}
	return revoked, nil
}

func (s *Server) generateAndSaveServer(ctx context.Context, hostname, ipStr, env, sshUser string) (string, string, error) {
	// 1. Generate RSA Key
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", "", err
	}
	
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}
	privPEM := string(pem.EncodeToMemory(&privBlock))

	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", err
	}
	pubAuthorizedKey := string(ssh.MarshalAuthorizedKey(pub))
	fingerprint := ssh.FingerprintSHA256(pub)

	// 2. Write to Vault
	vaultPath := fmt.Sprintf("secret/data/ssh/%s", hostname)
	err = s.Vault.PutSecret(ctx, vaultPath, privPEM, fingerprint)
	if err != nil {
		return "", "", fmt.Errorf("vault provision failed: %v", err)
	}

	// 3. Insert into Database
	_, err = s.DB.Exec("INSERT INTO servers (hostname, private_ip, vault_secret_path, environment, ssh_user) VALUES ($1, $2, $3, $4, $5)", hostname, ipStr, vaultPath, env, sshUser)
	if err != nil {
		return "", "", fmt.Errorf("db insert failed: %v", err)
	}

	return pubAuthorizedKey, privPEM, nil
}

func (s *Server) saveCustomServer(ctx context.Context, hostname, ipStr, env, sshUser, privPEM string) error {
	// 1. Parse Private Key to get fingerprint
	signer, err := ssh.ParsePrivateKey([]byte(privPEM))
	if err != nil {
		return fmt.Errorf("invalid private key provided: %v", err)
	}
	fingerprint := ssh.FingerprintSHA256(signer.PublicKey())

	// 2. Write to Vault
	vaultPath := fmt.Sprintf("secret/data/ssh/%s", hostname)
	err = s.Vault.PutSecret(ctx, vaultPath, privPEM, fingerprint)
	if err != nil {
		return fmt.Errorf("vault provision failed: %v", err)
	}

	// 3. Insert into Database
	_, err = s.DB.Exec("INSERT INTO servers (hostname, private_ip, vault_secret_path, environment, ssh_user) VALUES ($1, $2, $3, $4, $5)", hostname, ipStr, vaultPath, env, sshUser)
	if err != nil {
		return fmt.Errorf("db insert failed: %v", err)
	}

	return nil
}

func (s *Server) autoProvisionKey(ip, sshUser, sshPass, pubKey string) error {
	config := &ssh.ClientConfig{
		User: sshUser,
		Auth: []ssh.AuthMethod{
			ssh.Password(sshPass),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	targetAddr := fmt.Sprintf("%s:22", ip)
	client, err := ssh.Dial("tcp", targetAddr, config)
	if err != nil {
		return fmt.Errorf("ssh dial failed (incorrect credentials or offline): %v", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to open session: %v", err)
	}
	defer session.Close()

	cmd := fmt.Sprintf("mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '%s' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys", strings.TrimSpace(pubKey))
	err = session.Run(cmd)
	if err != nil {
		return fmt.Errorf("failed to inject key: %v", err)
	}

	return nil
}

func (s *Server) readKey(conn net.Conn) (string, error) {
	buf := make([]byte, 1)
	_, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	
	if buf[0] == 0x1b {
		b2 := make([]byte, 2)
		conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		n, _ := io.ReadFull(conn, b2)
		conn.SetReadDeadline(time.Time{})
		if n == 2 && b2[0] == '[' {
			switch b2[1] {
			case 'A': return "UP", nil
			case 'B': return "DOWN", nil
			case 'C': return "RIGHT", nil
			case 'D': return "LEFT", nil
			}
		}
		return "ESC", nil
	}
	
	if buf[0] == 13 || buf[0] == 10 {
		return "ENTER", nil
	}
	if buf[0] == 127 || buf[0] == 8 {
		return "BACKSPACE", nil
	}
	if buf[0] == 3 {
		return "CTRL_C", nil
	}
	if buf[0] == 19 {
		return "CTRL_S", nil
	}
	
	return string(buf), nil
}
