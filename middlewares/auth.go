package middlewares

import (
	"net/http"

	"github.com/Papurudoragon/cve5api/utils"
	"github.com/gin-gonic/gin"
)

func GetAuthentication(context *gin.Context) {
	// token for auth header
	token := context.Request.Header.Get("Authorization")

	if token == "" {
		context.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Authenticaton Failed"})
		return
	}

	// verify the token
	userId, err := utils.VerifyToken(token)

	if err != nil {
		context.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Authentication Failed."})
	}

	// set the context for calling from memory
	context.Set("userId", userId) // This isnt used yet but will be used later
	context.Next()
}
