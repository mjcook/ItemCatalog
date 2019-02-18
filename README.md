# Project Title

Item Catalog

In Python, flask is micro webframework used to build an Item catalogging web application. This web application is supported by a sqlite database which is interfaced with in python using sqlalchemy. Primarily using these two tools, an Item Catalog Web Application was designed to do the following:

1. Implement JSON endpoints to retrieve information about items/categories
2. Perform CRUD operations on database entries and checking for authorization
3. Creating Users/Logging in/Logging out
4. Implementing third party authentication/authorization using OAuth2.0

## Getting Started

What you need to do before executing the flask micro webframework app: application.py

### Prerequisites

What things you need to install to run the LogAnalysis.py

- A unix-style terminal such as Git Bash
    - http://www.git-scm.com

- Linux-based virtual machine (VM) this will give the postgreSQL database and support software
    - https://www.virtualbox.org/wiki/Download_Old_Builds_5_1
    - https://www.vagrantup.com/downloads.html

- Vagrant File will provide the virtual machine in order to run the generate the news database and run the python script
    -  https://github.com/udacity/fullstack-nanodegree-vm

- catalog.zip will provide the following files/folders:
    - application.py
    - catalog.py
    - client_secrets.json
    - static (contains css)
    - templates (contains html)

- Python 2.7 is used to run the code 
    - https://www.python.org/download/releases/2.7/


### Installing

Download the python library to connect to the news database

1) Open a terminal such as git bash
2) Navigate to the directory where the Vagrant File has been installed to
3) Run the following command: vagrant up
4) Once done, run the folloiwng comand: vagrant ssh
5) Change directory to the /vagrant folder
6) Extract the catalog folder from the catalog.zip file
7) Move the catalog folder to the /vagrant folder in your terminal window
8) Change directories in your terminal so your current directory is the /vagrant/catalog folder
9) Run the following command in your terminal window: ls
10) Make sure the output displays that all of the files/folders from the catalog.zip file are now present
11) Execute the following command in order to generate catalog database: python catalog.py

## Running the server

Inside of the terminal in the catalog subdirectory, execute the following command: python application.py

The following output should be generated

```
 * Serving Flask app "application" (lazy loading)
 * Environment: production
   WARNING: Do not use the development server in a production environment.
   Use a production WSGI server instead.
 * Debug mode: on
 * Running on http://0.0.0.0:5000/ (Press CTRL+C to quit)
 * Restarting with stat
 * Debugger is active!
 * Debugger PIN: 'SOME-PIN-HERE'
```

### Interacting with the server

In your broswer, navigate to http://localhost:5000

NOTE LOGIN USING GOOGLE REQUIRES CLIENT_SECRETS.JSON FROM GOOGLE WHICH WAS REMOVED FROM THIS REPO FOR PRIVACY REASONS

From here you can do the following:

1) Login using your google account or create new users in order to log in
2) Create new categories
3) Create new items within each category (assuming you are logged in as the user who created that category)
4) Edit/Update/Delete categories/items (assuming you are logged in as the user who created that category/item)
5) Access JSON End Points:
    1) /catalog/<category_id>/<item_id>/json
    2) /catalog/<category_id>/json
    3) /catalog/json

## Versioning

Version 1.0

## Authors

- **Mitchell Cook**
