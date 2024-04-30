package db

import (
	"github.com/Papurudoragon/cve5api/utils"
)

func createUsersTable() {
	createUsersTable := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL,
		email TEXT NOT NULL
	)
	`
	_, err := DB.Exec(createUsersTable)

	if err != nil {
		panic("Unable to create users table")
	}

	// create an admin user if not exists --> you can always change the password later
	createAdminUser := `
	INSERT OR IGNORE INTO users (
		username,
		password,
		email
	) VALUES (
		?, ?, ?
	);
	`

	stmt, err := DB.Prepare(createAdminUser)

	if err != nil {
		panic("failed to add admin user to users table.")
	}

	// use hashed password for password
	hashedPass, err := utils.HashPassword("password")

	if err != nil {
		panic("failed to update admin default password to user table")
	}

	_, err = stmt.Exec(
		"admin",
		hashedPass,
		"admin@emailhere.xyz",
	)

	if err != nil {
		panic("failed to add admin user to users table.")
	}

}
