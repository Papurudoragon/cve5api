# CVE version 5.0 API 

**by papv2**

The latest version of CVE (5.0) is available. This api simply pulls data from that repository, and allows for querying the data based on search parameters.


# Install

**requires go1.21 to install successfully. Run the following command to install the latest version:**

```
go install github.com/Papurudoragon/cve5api@latest

now you should just be able to run 'cve5api' in the cli to start the api
```


**Notes**

    The API uses a GET request, so a standard browser or cli GET should suffice to use.

    Content-Type: application/json *MUST* be used in the request

# Usage

```
    GET http://<ip or url>:8080/api/cve?parameter1=valu1&parameter2=value2
    Content-Type: application/json
```



**Available Parameters for searching**

    - `cve_id`: Search by CVE ID (entire ID or a portion).
    - `keyword`: Search by keyword (for a phrase, use `+` instead of space).
    - `assigner_name`: Search by name of the assigned CVE publisher (entire name or a portion).
    - `update_date`: Search by update date (yyyy-mm-dd format).
    - `publish_date`: Search by publish date (yyyy-mm-dd format).
    - `vendor`: Search by vendor name (entire name or a portion).
    - `product`: Search by product name (entire name or a portion).
    - `version`: Search by listed product version (or part of the version).
    - `type`: Search by vulnerability type (choices are either `cwe` or `text`).
    - `type_description`: Search by vulnerability type description (a CWE or General Vulnerability description, e.g., improper access controls).



**Example**

```
    GET http://127.0.0.1:8080/api/cve?cve=2024&keyword=wordpress&type=cwe
    Content-Type: application/json
```



# Installing the API to host Locally

    1. Clone this repository
    
    2. run cve5api (for windows, just run the .exe file) -- see install instructions above

    3. one the api starts, send a POST request to login with the admin account 
        a. Login for default account:

            POST  http://127.0.0.1:8080/api/users/login
            Content-Type: application/json

            {
                "username": "admin",
                "password": "password",
                "email": "admin@emailhere.xyz"
            }

    4. The API will return a jwt token for Authorization and further admin function (expires in 2 hours)

    5. send an update request to the API To populate data into your local db (*NOTE*: This WILL take quite some time, sometimes up to an hour). Upon completion, you should see somethign like this in API logs: 

        ```| 200 |        55m53s |       127.0.0.1 | POST     "/api/update"```

        a. Update request for API:

            ```POST http://127.0.0.1:8080/api/update
            Content-Type: application/json
            Authorization: <jwt token>```

    6. Your API is ready to use via search functions and get requests above




#Available Admin paths (Requires a valid jwt token for actions)

```
/api/users/login                    --> Login with an admin account
/api/users/update/<id_number>       --> Update a single user by ID 
/api/users/delete/<id_number>       --> Delete a single user by ID
/api/users/<id_number>              --> Fetch user information by ID
/api/users                          --> Fetch all users
/api/update                         --> Update the DB with latest CVE 5.0 updates
/api/delete                         --> Delete local copy of CVE DB (not recommended unless the db is giving issues)
/api/users/create                   --> Create a new admin user
```



    




    
