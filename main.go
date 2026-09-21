package main

import (
	"fmt"

	"github.com/joho/godotenv"

	"github.com/MustaphaSakka/traney-auth/app"
)

func main() {
	godotenv.Load()
	fmt.Println("traney-auth is started!")
	app.Start()

}
