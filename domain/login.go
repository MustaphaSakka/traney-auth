package domain

import (
	"database/sql"
	"strings"
	"time"

	"github.com/MustaphaSakka/traney-lib/exception"
	"github.com/MustaphaSakka/traney-lib/logger"
	"github.com/golang-jwt/jwt/v5"
)

const TOKEN_DURATION = time.Hour

type Login struct {
	Username string         `db:"username"`
	ClientId sql.NullString `db:"client_id"`
	Accounts sql.NullString `db:"account_numbers"`
	Role     string         `db:"role"`
}

func (l Login) GenerateToken() (*string, *exception.AppException) {
	var claims jwt.MapClaims
	if l.Accounts.Valid && l.ClientId.Valid {
		claims = l.claimsForUser()
	} else {
		claims = l.claimsForAdmin()
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedTokenAsString, err := token.SignedString([]byte(HMAC_SAMPLE_SECRET))
	if err != nil {
		logger.Error("Failed while signing token: " + err.Error())
		return nil, exception.InternalServerException("cannot generate token")
	}
	return &signedTokenAsString, nil
}

func (l Login) claimsForUser() jwt.MapClaims {
	accounts := strings.Split(l.Accounts.String, ",")
	return jwt.MapClaims{
		"client_id": l.ClientId.String,
		"role":      l.Role,
		"username":  l.Username,
		"accounts":  accounts,
		"exp":       time.Now().Add(TOKEN_DURATION).Unix(),
	}
}

func (l Login) claimsForAdmin() jwt.MapClaims {
	return jwt.MapClaims{
		"role":     l.Role,
		"username": l.Username,
		"exp":      time.Now().Add(TOKEN_DURATION).Unix(),
	}
}
