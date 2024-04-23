package app

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/MustaphaSakka/traney-auth/domain"
	"github.com/MustaphaSakka/traney-auth/service"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
)

func Start() {
	router := mux.NewRouter()

	authRepository := domain.NewAuthRepository(getDbClient())
	ah := AuthHandler{service.NewLoginService(authRepository, domain.GetRolePermissions())}

	router.HandleFunc("/auth/login", ah.Login).Methods(http.MethodPost)

	// starting server
	log.Fatal(http.ListenAndServe("localhost:8888", router))
}

func getDbClient() *sqlx.DB {
	client, err := sqlx.Open("mysql", "root:@/traney")
	if err != nil {
		panic(err)
	}

	fmt.Println("Connexion to database is established.")

	client.SetConnMaxLifetime(time.Minute * 3)
	client.SetMaxOpenConns(10)
	client.SetMaxIdleConns(10)
	return client
}
