package db

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3" // _ tells go we need this import so dont remove
)

var DB *sql.DB

const maxOpenConn int = 15
const maxIdleConn int = 5

// initialize db
func InitDB() {
	var err error

	DB, err = sql.Open("sqlite3", "cve.db")

	if err != nil {
		panic("Unable to connect to database")
	}

	DB.SetMaxOpenConns(maxOpenConn)
	DB.SetMaxIdleConns(maxIdleConn)

	createCVETables()
	createUsersTable()

}

func createCVETables() {
	// Create containers table
	createCVETable := `
	CREATE TABLE IF NOT EXISTS cve_container (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		dataType VARCHAR(255),
		dataVersion VARCHAR(255),
		state VARCHAR(255),
		cveID VARCHAR(255) UNIQUE,
		assignerOrgID VARCHAR(255),
		assignerShortName VARCHAR(255),
		dateUpdated TIMESTAMP,
		dateReserved TIMESTAMP,
		datePublished TIMESTAMP,
		orgID VARCHAR(255),
		shortName VARCHAR(255),
		providerDateUpdated TIMESTAMP,
		description_lang VARCHAR(255),
		description_value TEXT,
		vendor VARCHAR(255),
		product VARCHAR(255),
		version VARCHAR(255),
		status VARCHAR(255),
		url VARCHAR(255),
		types_type VARCHAR(255),
		types_lang VARCHAR(255),
		description TEXT
	); 
	` // cveID is a UNIQUE table to avoid duplicates (though this may drop extra affected products, but does it really matter?)
	_, err := DB.Exec(createCVETable)

	if err != nil {
		panic(err)
	}

	// Index cve_containers table for searching faster

	indexCVETable := `
	CREATE INDEX IF NOT EXISTS cve_container_query_fields_idx
	ON cve_container(cveID, description_value, assignerShortName, dateUpdated, datePublished, vendor, product, version, types_type, description);
	`

	_, err = DB.Exec(indexCVETable)

	if err != nil {
		panic(err)
	}

}
