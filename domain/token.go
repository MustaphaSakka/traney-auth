package domain

import (
	"github.com/golang-jwt/jwt/v5"
)

const HMAC_SAMPLE_SECRET = "hmacSampleSecret"

type Claims struct {
	ClientId string   `json:"Client_id"`
	Accounts []string `json:"accounts"`
	Username string   `json:"username"`
	Expiry   int64    `json:"exp"`
	Role     string   `json:"role"`
	jwt.RegisteredClaims
}

func (c Claims) IsUserRole() bool {
	return c.Role == "user"
}

// func BuildClaimsFromJwtMapClaims(mapClaims jwt.MapClaims) (*Claims, error) {
// 	bytes, err := json.Marshal(mapClaims)
// 	if err != nil {
// 		return nil, err
// 	}
// 	var c Claims
// 	err = json.Unmarshal(bytes, &c)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return &c, nil
// }

func (c Claims) IsValidClientId(ClientId string) bool {
	return c.ClientId == ClientId
}

func (c Claims) IsValidAccountId(accountId string) bool {
	if accountId != "" {
		accountFound := false
		for _, a := range c.Accounts {
			if a == accountId {
				accountFound = true
				break
			}
		}
		return accountFound
	}
	return true
}

func (c Claims) IsRequestVerifiedWithTokenClaims(urlParams map[string]string) bool {
	if c.ClientId != urlParams["Client_id"] {
		return false
	}

	if !c.IsValidAccountId(urlParams["account_id"]) {
		return false
	}
	return true
}
