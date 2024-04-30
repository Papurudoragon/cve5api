package routes

import (
	"net/http"
	"strconv"

	"github.com/Papurudoragon/cve5api/model"
	"github.com/Papurudoragon/cve5api/utils"
	"github.com/gin-gonic/gin"
)

func createUser(context *gin.Context) {
	var user model.User
	err := context.ShouldBindJSON(&user)

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"message": "Create User Failed."})
		return
	}

	err = user.Save()

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"message": "Could not create user"})
		return
	}

	context.JSON(http.StatusCreated, gin.H{"message": "User has been created successfully"})

}

func userLogin(context *gin.Context) {
	var user model.User
	err := context.ShouldBindJSON(&user)

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"message": "Login Failed."})
		return
	}

	err = user.ValidateCredentials()

	if err != nil {
		context.JSON(http.StatusUnauthorized, gin.H{"message": "user authentication failed"})
		return
	}

	token, err := utils.GenerateToken(user.UserEmail, user.Id)

	if err != nil {
		context.JSON(http.StatusUnauthorized, gin.H{"message": "user authentication failed"})
		return
	}

	context.JSON(http.StatusOK, gin.H{"message": "Authentication Success!", "token": token})

}

func userPasswordUpdate(context *gin.Context) {
	var user model.User
	err := context.ShouldBindJSON(&user)

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"message": "Invalid Parameters"})
		return
	}

	err = user.UpdateUserPassword(user.UserPassword)

	if err != nil {
		context.JSON(http.StatusUnauthorized, gin.H{"message": "user authentication failed"})
		return
	}

	context.JSON(http.StatusOK, gin.H{"message": "User updated successfully!"})

}

func userAccountDelete(context *gin.Context) {
	var user model.User
	err := context.ShouldBindJSON(&user)

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"message": "Update user failed."})
		return
	}

	err = user.DeleteUser()

	if err != nil {
		context.JSON(http.StatusUnauthorized, gin.H{"message": "user deletion failed"})
		return
	}

	context.JSON(http.StatusOK, gin.H{"message": "User successfully deleted!"})

}

func userGetAll(context *gin.Context) {

	users, err := model.GetAllUsers()

	if err != nil {
		context.JSON(http.StatusInternalServerError, gin.H{"message": "get user query failed"})
		return
	}

	context.JSON(http.StatusOK, users)

}

func getSingleUser(context *gin.Context) {
	var user model.User
	singleUserId, err := strconv.ParseInt(context.Param("id"), 10, 64)

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"message": "Could not fetch userId."})
		return
	}

	err = context.ShouldBindJSON(&user)

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"message": "get user query failed"})
		return
	}

	userId := context.GetInt64("id") //should be userId but we can fix that later
	singleUser, err := model.GetSingleUsers(singleUserId)

	if err != nil {
		context.JSON(http.StatusInternalServerError, gin.H{"message": "Could not retrieve user information."})
		return
	}

	if user.Id != userId {
		context.JSON(http.StatusUnauthorized, gin.H{"message": "Not authorized to retrieve user information"})
		return
	}

	context.JSON(http.StatusOK, singleUser)

}
