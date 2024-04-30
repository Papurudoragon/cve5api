package model

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/Papurudoragon/cve5api/db"
	"github.com/go-git/go-git/v5"
)

// global vars
const repoDirectory string = "/tmp/cve/cves"
const rootDirectory string = "/tmp/cve"

var fileList []string // List of files to open and parse

type CVEData struct {
	ID          int64  `json:"id"`
	DataType    string `json:"dataType"`
	DataVersion string `json:"dataVersion"`
	CveMetadata struct {
		State             string `json:"state"`
		CveID             string `json:"cveId"`
		AssignerOrgID     string `json:"assignerOrgId"`
		AssignerShortName string `json:"assignerShortName"`
		DateUpdated       string `json:"dateUpdated"`
		DateReserved      string `json:"dateReserved"`
		DatePublished     string `json:"datePublished"`
	} `json:"cveMetadata"`
	Containers struct {
		Cna struct {
			ProviderMetadata struct {
				OrgID       string `json:"orgId"`
				ShortName   string `json:"shortName"`
				DateUpdated string `json:"dateUpdated"`
			} `json:"providerMetadata"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Affected []struct {
				Vendor   string `json:"vendor"`
				Product  string `json:"product"`
				Versions []struct {
					Version string `json:"version"`
					Status  string `json:"status"`
				} `json:"versions"`
			} `json:"affected"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
			ProblemTypes []struct {
				Descriptions []struct {
					Type        string `json:"type"`
					Lang        string `json:"lang"`
					Description string `json:"description"`
				} `json:"descriptions"`
			} `json:"problemTypes"`
		} `json:"cna"`
	} `json:"containers"`
}

// method to save fields into container db (initial commit)
func (c *CVEData) Save() error {
	tx, err := db.DB.Begin()

	if err != nil {
		return err
	}

	// rollback if update fails
	defer func() {
		if err != nil {
			tx.Rollback()
		} else {
			err = tx.Commit()
		}

	}() // execute inline

	query := `
		INSERT OR REPLACE INTO cve_container (
			dataType,
			dataVersion,
			state,
			cveID,
			assignerOrgID,
			assignerShortName,
			dateUpdated,
			dateReserved,
			datePublished,
			orgID,
			shortName,
			providerDateUpdated,
			description_lang,
			description_value,
			vendor,
			product,
			version,
			status,
			url,
			types_type,
			types_lang,
			description
		) VALUES (
			?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
		);
	`

	stmt, err := tx.Prepare(query)
	if err != nil {
		return err
	}

	// Insert data into cve_container table
	for _, description := range c.Containers.Cna.Descriptions {
		for _, affected := range c.Containers.Cna.Affected {
			for _, versions := range affected.Versions {
				for _, ref := range c.Containers.Cna.References {
					for _, problemType := range c.Containers.Cna.ProblemTypes {
						for _, pDescription := range problemType.Descriptions {
							result, err := stmt.Exec(
								c.DataType,
								c.DataVersion,
								c.CveMetadata.State,
								c.CveMetadata.CveID,
								c.CveMetadata.AssignerOrgID,
								c.CveMetadata.AssignerShortName,
								c.CveMetadata.DateUpdated,
								c.CveMetadata.DateReserved,
								c.CveMetadata.DatePublished,
								c.Containers.Cna.ProviderMetadata.OrgID,
								c.Containers.Cna.ProviderMetadata.ShortName,
								c.Containers.Cna.ProviderMetadata.DateUpdated,
								description.Lang,
								description.Value,
								affected.Vendor,
								affected.Product,
								versions.Version,
								versions.Status,
								ref.URL,
								pDescription.Type,
								pDescription.Lang,
								pDescription.Description,
							)

							if err != nil {
								return err
							}

							// increment ID field
							id, err := result.LastInsertId()

							if err != nil {
								return err
							}

							c.ID = id
						}
					}
				}
			}

		}
	}

	return err
}

func fetchCVEDetails() {

	// clone the new directory
	_, err := git.PlainClone(repoDirectory, false, &git.CloneOptions{
		URL: "https://github.com/CVEProject/cvelistV5.git",
	})

	if err != nil {
		log.Fatal(err)
	}

	OutputJSONToSlice()
	readJSONSlice()

}

// walk the directories in tmp to grab js files
func FilePathWalkDir(root string) ([]string, error) {
	var files []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

// output all file paths to a slice
func OutputJSONToSlice() {

	err := filepath.Walk(repoDirectory, func(path string, info os.FileInfo, err error) error {

		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		// Grab the names of our .json file paths to import to db later
		if filepath.Ext(path) == ".json" && strings.Contains(path, "CVE") {
			fileList = append(fileList, path)
		}

		return err

	})

	if err != nil {
		log.Fatal(err)
	}

}

// read the json slice and append to our struct
func readJSONSlice() {

	for _, files := range fileList {

		file, err := os.Open(files)
		if err != nil {
			log.Println("Error opening file:", err)
			continue
		}

		defer file.Close()

		byteValue, err := io.ReadAll(file)

		if err != nil {
			log.Fatal(err)
		}

		c := CVEData{}

		json.Unmarshal([]byte(byteValue), &c)

		err = c.Save()

		if err != nil {
			log.Fatal(err)
		}

	}
}

// need to make a backup of both the db and repo before updating
func backupData() {
	// Check if the root directory exists
	_, err := os.Stat(rootDirectory)

	// If the directory exists, rename it
	if !os.IsNotExist(err) {

		// Check if the old root directory exists
		oldDirectory := rootDirectory + "_old"
		_, err := os.Stat(oldDirectory)

		// If the old root directory exists, remove it
		if !os.IsNotExist(err) {
			err = os.RemoveAll(oldDirectory)
			if err != nil {
				fmt.Println("Backup not found, Continuing..")
			}
		}

		// Rename the current root directory to .old so that we can initiate a new clone
		err = os.Rename(rootDirectory, oldDirectory)
		if err != nil {
			log.Fatal(err)
		}
	}

	/////// To Do, also make a backup of the db
}

// Method to update the DB
func UpdateDB() error {
	backupData()
	fetchCVEDetails()
	return nil
}

// This deletes the entire db, dont use (only for Admins)
func DeleteDB() error {
	query := `
	DELETE FROM cve_container;
	`

	stmt, err := db.DB.Prepare(query)
	if err != nil {
		return err
	}

	defer stmt.Close()

	return err

}
