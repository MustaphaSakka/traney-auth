package domain

import (
	"database/sql"

	"github.com/MustaphaSakka/traney-lib/exception"
	"github.com/MustaphaSakka/traney-lib/logger"
	"github.com/jmoiron/sqlx"
)

type AuthRepository interface {
	FindBy(username string, password string) (*Login, *exception.AppException)
}

type AuthRepositoryDb struct {
	client *sqlx.DB
}

func (d AuthRepositoryDb) FindBy(username, password string) (*Login, *exception.AppException) {
	var l Login
	sqlVerify := `SELECT username, u.client_id, role, group_concat(a.account_id) as account_numbers FROM users u
                  LEFT JOIN accounts a ON a.client_id = u.client_id
                WHERE username = ? and password = ?
                GROUP BY a.client_id`

	err := d.client.Get(&l, sqlVerify, username, password)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, exception.AuthenticationError("invalid credentials")
		} else {
			logger.Error("Error while verifying login request from database: " + err.Error())
			return nil, exception.InternalServerException("unexpected database error")
		}
	}
	return &l, nil
}

func NewAuthRepository(client *sqlx.DB) AuthRepositoryDb {
	return AuthRepositoryDb{client}
}
