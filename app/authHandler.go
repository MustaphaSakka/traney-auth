package app

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/MustaphaSakka/traney-auth/dto"
	"github.com/MustaphaSakka/traney-auth/service"
)

type AuthHandler struct {
	service service.AuthService
}

func (h AuthHandler) NotImplementedHandler(w http.ResponseWriter, r *http.Request) {
	writeResponse(w, http.StatusOK, "Handler not implemented...")
}

func (h AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var loginRequest dto.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&loginRequest); err != nil {
		log.Println("Error while decoding login request: " + err.Error())
		w.WriteHeader(http.StatusBadRequest)
	} else {
		token, err := h.service.Login(loginRequest)
		if err != nil {
			writeResponse(w, http.StatusUnauthorized, err.Error())
		} else {
			writeResponse(w, http.StatusOK, *token)
		}
	}
}

func notAuthorizedResponse() map[string]bool {
	return map[string]bool{"isAuthorized": false}
}

func authorizedResponse() map[string]bool {
	return map[string]bool{"isAuthorized": true}
}

func writeResponse(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		panic(err)
	}
}
