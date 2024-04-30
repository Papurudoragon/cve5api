package main

import (
	"github.com/Papurudoragon/cve5api/db"
	"github.com/Papurudoragon/cve5api/routes"
	"github.com/gin-gonic/gin"
)

func main() {
	// nitizialize DB
	db.InitDB()

	// Start db after all checks
	server := gin.Default()
	routes.RegisterRouter(server)
	server.Run(":8080")

}

// To Do:

// add 2fa with OTP
// Optimize search parameters
// Optimize update feature
// better db auth
// better dt indexing and querying
