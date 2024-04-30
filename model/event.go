package model

import (
	"errors"

	"github.com/Papurudoragon/cve5api/db"
)

// redefine individual structs, from the main struct (only those that have slices), to use in our search query
// redefine the Affected struct
type Affected struct {
	Vendor   string `json:"vendor"`
	Product  string `json:"product"`
	Versions []struct {
		Version string `json:"version"`
		Status  string `json:"status"`
	} `json:"versions"`
}

// redefine the ProblemType Struct
type ProblemTypes struct {
	Descriptions []struct {
		Type        string `json:"type"`
		Lang        string `json:"lang"`
		Description string `json:"description"`
	} `json:"descriptions"`
}

func SearchCVENumberByKeyword(cveid, description, assignerName, updateDate, publishDate, vendor, product, version, vulnerabilityType, typeDescription string) ([]CVEData, error) {
	query := `
	SELECT * FROM cve_container WHERE cveID LIKE ? AND description_value LIKE ? AND assignerShortName LIKE ? AND dateUpdated LIKE ? AND datePublished LIKE ? AND vendor LIKE ? AND product LIKE ? AND version LIKE ? and types_type LIKE ? AND description LIKE ? ORDER BY id DESC;
	`

	// wildcards for LIKE query
	cveid = "%" + cveid + "%"
	description = "%" + description + "%"
	assignerName = "%" + assignerName + "%"
	updateDate = "%" + updateDate + "%"
	publishDate = "%" + publishDate + "%"
	vendor = "%" + vendor + "%"
	product = "%" + product + "%"
	version = "%" + version + "%"
	vulnerabilityType = "%" + vulnerabilityType + "%"
	typeDescription = "%" + typeDescription + "%"

	rows, err := db.DB.Query(
		query,
		cveid,
		description,
		assignerName,
		updateDate,
		publishDate,
		vendor,
		product,
		version,
		vulnerabilityType,
		typeDescription,
	)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cveDataList []CVEData

	for rows.Next() {
		var cveData CVEData
		var descriptionValue, affectedProduct, affectedVendor, affectedVersion, affectedStatus, pDescriptionType, pDescriptionLang, pDescriptionDescription, referenceURL string
		descriptionLang := "en"

		// Scan the row data into variables
		err := rows.Scan(
			&cveData.ID,
			&cveData.DataType,
			&cveData.DataVersion,
			&cveData.CveMetadata.State,
			&cveData.CveMetadata.CveID,
			&cveData.CveMetadata.AssignerOrgID,
			&cveData.CveMetadata.AssignerShortName,
			&cveData.CveMetadata.DateUpdated,
			&cveData.CveMetadata.DateReserved,
			&cveData.CveMetadata.DatePublished,
			&cveData.Containers.Cna.ProviderMetadata.OrgID,
			&cveData.Containers.Cna.ProviderMetadata.ShortName,
			&cveData.Containers.Cna.ProviderMetadata.DateUpdated,
			&descriptionLang,
			&descriptionValue,
			&affectedProduct,
			&affectedVendor,
			&affectedVersion,
			&affectedStatus,
			&referenceURL, // change this to iterate later
			&pDescriptionType,
			&pDescriptionLang,
			&pDescriptionDescription,
		)
		if err != nil {
			return nil, errors.New("failed to query for data")
		}

		// add Description struct
		description := struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		}{
			Lang:  descriptionLang,
			Value: descriptionValue,
		}

		// add Affected struct with correct Versions field to append
		affected := Affected{
			Vendor:  affectedVendor,
			Product: affectedProduct,
			Versions: []struct {
				Version string `json:"version"`
				Status  string `json:"status"`
			}{
				{
					Version: affectedVersion,
					Status:  affectedStatus,
				},
			},
		}

		// add problemType description struct
		pDescription := ProblemTypes{
			Descriptions: []struct {
				Type        string `json:"type"`
				Lang        string `json:"lang"`
				Description string `json:"description"`
			}{
				{
					Type:        pDescriptionType,
					Lang:        pDescriptionLang,
					Description: pDescriptionDescription,
				},
			},
		}

		references := struct {
			URL string `json:"url"`
		}{
			URL: referenceURL,
		}

		cveData.Containers.Cna.Descriptions = append(cveData.Containers.Cna.Descriptions, description)
		cveData.Containers.Cna.Affected = append(cveData.Containers.Cna.Affected, affected)
		cveData.Containers.Cna.ProblemTypes = append(cveData.Containers.Cna.ProblemTypes, pDescription)
		cveData.Containers.Cna.References = append(cveData.Containers.Cna.References, references)
		cveDataList = append(cveDataList, cveData)
	}

	return cveDataList, nil
}
