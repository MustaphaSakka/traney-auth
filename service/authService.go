package service

import (
	"fmt"

	"github.com/MustaphaSakka/traney-lib/exception"
	"github.com/MustaphaSakka/traney-lib/logger"

	"github.com/MustaphaSakka/traney-auth/domain"
	"github.com/MustaphaSakka/traney-auth/dto"
	"github.com/golang-jwt/jwt/v5"
)

type AuthService interface {
	Login(dto.LoginRequest) (*string, *exception.AppException)
	Verify(urlParams map[string]string) *exception.AppException
}

type DefaultAuthService struct {
	repo            domain.AuthRepository
	rolePermissions domain.RolePermissions
}

func (s DefaultAuthService) Login(req dto.LoginRequest) (*string, *exception.AppException) {
	login, err := s.repo.FindBy(req.Username, req.Password)
	if err != nil {
		return nil, err
	}
	token, err := login.GenerateToken()
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (s DefaultAuthService) Verify(urlParams map[string]string) *exception.AppException {
	// convert the string token to JWT struct
	if jwtToken, err := jwtTokenFromString(urlParams["token"]); err != nil {
		return exception.AuthorizationError(err.Error())
	} else {
		/*
		   Checking the validity of the token, this verifies the expiry
		   time and the signature of the token
		*/
		if jwtToken.Valid {
			claims := jwtToken.Claims.(*domain.Claims)
			/* if Role if user then check if the account_id and customer_id
			   coming in the URL belongs to the same token
			*/
			if claims.IsUserRole() {
				if !claims.IsRequestVerifiedWithTokenClaims(urlParams) {
					return exception.AuthorizationError("request not verified with the token claims")
				}
			}
			// verify of the role is authorized to use the route
			isAuthorized := s.rolePermissions.IsAuthorizedFor(claims.Role, urlParams["routeName"])
			if !isAuthorized {
				return exception.AuthorizationError(fmt.Sprintf("%s role is not authorized", claims.Role))
			}
			return nil
		} else {
			return exception.AuthorizationError("Invalid token")
		}
	}
}

func jwtTokenFromString(tokenString string) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, &domain.Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(domain.HMAC_SAMPLE_SECRET), nil
	})
	if err != nil {
		logger.Error("Error while parsing token: " + err.Error())
		return nil, err
	}
	return token, nil
}

func NewLoginService(repo domain.AuthRepository, permissions domain.RolePermissions) DefaultAuthService {
	return DefaultAuthService{repo, permissions}
}
