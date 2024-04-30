package routes

import (
	"github.com/Papurudoragon/cve5api/middlewares"
	"github.com/gin-gonic/gin"
)

func RegisterRouter(server *gin.Engine) {
	// search query
	server.GET("/api/cve", searchCVEsByKeyword)

	// admin features
	server.POST("/api/users/login", userLogin)
	server.PUT("/api/users/update/:id", middlewares.GetAuthentication, userPasswordUpdate)   // Admin function
	server.DELETE("/api/users/delete/:id", middlewares.GetAuthentication, userAccountDelete) // Admin function
	server.GET("/api/users/:id", middlewares.GetAuthentication, getSingleUser)               // Admin function
	server.GET("/api/users", middlewares.GetAuthentication, userGetAll)                      // Admin function

	// Migrated to admin only feature
	server.POST("/api/update", middlewares.GetAuthentication, updateCVEDatabase)   // Admin function
	server.DELETE("/api/delete", middlewares.GetAuthentication, deleteCVEDatabase) // admin only

	// Hide this behind admin credentials so only an admin can create users
	server.POST("/api/users/create", middlewares.GetAuthentication, createUser) // Admin function
}
