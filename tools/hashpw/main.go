package main

// tools/hashpw/main.go
// Utility to generate bcrypt password hashes for seeding the users table.
// Usage: go run ./tools/hashpw/ mypassword
// Output: $2a$12$... (paste into db/seed.sql)

import (
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: go run ./tools/hashpw/ <password>")
		os.Exit(1)
	}

	password := os.Args[1]
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error hashing password: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(hash))
}
