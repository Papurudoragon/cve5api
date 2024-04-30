package model

import (
	"errors"

	"github.com/Papurudoragon/cve5api/db"
	"github.com/Papurudoragon/cve5api/utils"
)

type User struct {
	Id           int64  `json:"id"`
	UserName     string `json:"username" binding:"required"`
	UserPassword string `json:"password" binding:"required"`
	UserEmail    string `json:"email" binding:"required"`
}

// save our user information after creation
func (u *User) Save() error {
	query := `INSERT INTO users(username, password, email) VALUES(?, ?, ?)`

	stmt, err := db.DB.Prepare(query)

	if err != nil {
		return err
	}

	defer stmt.Close()

	// hash our password field
	hashedPass, err := utils.HashPassword(u.UserPassword)

	if err != nil {
		return err
	}

	result, err := stmt.Exec(u.UserName, hashedPass, u.UserEmail)

	if err != nil {
		return err
	}

	id, err := result.LastInsertId()

	if err != nil {
		return err
	}

	u.Id = id

	return err

}

func (u *User) ValidateCredentials() error {
	query := `SELECT id, password FROM users WHERE email = ?`
	row := db.DB.QueryRow(query, u.UserEmail)

	var retrievedPassword string

	// compare password hashes for a match

	err := row.Scan(&u.Id, &retrievedPassword)

	if err != nil {
		return errors.New("invalid credentials")
	}

	passwordIsValid := utils.CheckPasswordHash(u.UserPassword, retrievedPassword)

	if !passwordIsValid {
		return errors.New("invalid credentials")
	}

	return nil
}

func (u *User) UpdateUserPassword(password string) error {
	query := `UPDATE users SET password = ? WHERE username = ?`

	stmt, err := db.DB.Prepare(query)

	if err != nil {
		return err
	}

	defer stmt.Close()

	hashedPassword, err := utils.HashPassword(password)

	if err != nil {
		return err
	}

	_, err = stmt.Exec(
		hashedPassword,
		u.UserName,
	)

	return err

}

func (u *User) DeleteUser() error {
	query := `DELETE FROM users WHERE id = ?`

	stmt, err := db.DB.Prepare(query)

	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec(u.Id)

	return err
}

// return id, username, and email of all users
func GetAllUsers() ([]User, error) {
	query := `SELECT id, username, email FROM users`

	rows, err := db.DB.Query(query)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var userList []User

	for rows.Next() {
		var user User
		err := rows.Scan(&user.Id, &user.UserName, &user.UserEmail) // read the contents of the row we are processing

		if err != nil {
			return nil, err
		}

		userList = append(userList, user)

	}

	return userList, nil
}

// return username and id of single users
func GetSingleUsers(id int64) (*User, error) {
	query := `SELECT * FROM users WHERE id = ?`
	row := db.DB.QueryRow(query, id)

	var user User

	err := row.Scan(&user.Id, &user.UserName, &user.UserEmail)

	if err != nil {
		return nil, err
	}

	return &user, nil
}
