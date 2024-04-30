package routes

import (
	"net/http"

	"github.com/Papurudoragon/cve5api/model"
	"github.com/gin-gonic/gin"
)

func searchCVEsByKeyword(context *gin.Context) {
	// define our search params
	cveid := context.Query("cve_id")
	description := context.Query("keyword")
	assignerName := context.Query("assigner_name")
	updateDate := context.Query("update_date")
	publishDate := context.Query("publish_date")
	vendor := context.Query("vendor")
	product := context.Query("product")
	version := context.Query("version")
	vulnerabilityType := context.Query("type") // text or cwe
	typeDescription := context.Query("type_description")

	result, err := model.SearchCVENumberByKeyword(cveid, description, assignerName, updateDate, publishDate, vendor, product, version, vulnerabilityType, typeDescription)

	if err != nil {
		context.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to get CVE information"})
		return
	}

	// return only 1,000 results to avoid crashing things
	if len(result) >= 1001 {
		result = result[:1000]
	}

	context.JSON(http.StatusOK, result)

}

// update DB
func updateCVEDatabase(context *gin.Context) {

	err := model.UpdateDB()

	if err != nil {
		context.JSON(http.StatusUnauthorized, gin.H{"message": "Failed to update the CVE database"})
		return
	}

	context.JSON(http.StatusOK, gin.H{"message": "Successfully updated the CVE Database!"})

}

func deleteCVEDatabase(context *gin.Context) {

	err := model.DeleteDB()

	if err != nil {
		context.JSON(http.StatusUnauthorized, gin.H{"message": "Failed to delete the CVE database"})
		return
	}

	context.JSON(http.StatusOK, gin.H{"message": "Successfully deleted the CVE Database!"})

}
