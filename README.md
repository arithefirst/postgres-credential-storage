# Postgres Credential Storage
A simple system to store user credentials in postgres utilizing salts and SHA256, 
implemented in go. Created by [arithefirst](https://arithefirst.com).
# Docs
## Prerequisites
In order to use this library, you must have a table in your database with the properties shown<br> 
below. If your table does not have these properties, or is not named `login`, this library will<br>
not work. Your table can have more columns than show, but must have these 3 at least.
```SQL
CREATE TABLE login (
    username text unique,
    salt text,
    hash text
)
```

## Connecting to your DB
In order to connect to your DB, you need to create a variable or const of type<br>
`pcs.PostgresConnection`. You can then populate this variable with the connection<br>
details for your PostgreSQL server.

```golang
package main
import pcs "github.com/arithefirst/postgres-credential-storage"

func main() {
	connection := pcs.PostgresConnection{
		Host: "localhost",
		Port: 5432,
		User: "postgres",
		Pass: "postgres",
		Db:   "users",
		SSL:  false,
	}
}
```

## Hashing and Salting plaintext credentials
PCS Comes with a function to Hash and Salt your credentials for you from plaintext.<br> 
Just run the `pcs.SetPassword()` function with the required parameters, and it will<br>
store the password's salt and hash in the DB. All you need to pass in is your variable <br>
of type `pcs.PostgresConnection`, username, and password. The password is then <br>
salted, SHA256 Hashed, and added to the DB.

```golang
func main() {
	err := pcs.SetPassword("johnsmith@example.com", "password123", connection)
	if err != nil {
		panic(err)
	}
}
```
Output:
```
+-----------------------+----------------------------------+------------------------------------------------------------------+
| username              | salt                             | hash                                                             |
+-----------------------+----------------------------------+------------------------------------------------------------------+
| johnsmith@example.com | ^5@gVJN8>5p$67qXku2b6Oe6!#Z7Bd5c | 8993f6ad6e8539c0382ef40b3a320501d561d8e8eeceaaaeb59efcea6b7083b1 |
+-----------------------+----------------------------------+------------------------------------------------------------------+
```

## Storing pre-encrypted credentials
If you need to store a password that has already been salted and hashed, you can run <br>
`pcs.setPasswordNoHash` with the connection variable, plaintext salt, and the SHA256 hash.
```golang
func main() {
	err := pcs.SetPasswordNoHash("johnsmith@example.com",
		"8993f6ad6e8539c0382ef40b3a320501d561d8e8eeceaaaeb59efcea6b7083b1",
		"^5@gVJN8>5p$67qXku2b6Oe6!#Z7Bd5c", connection)
	if err != nil {
		panic(err)
	}
}
```
Output:
```
+-----------------------+----------------------------------+------------------------------------------------------------------+
| username              | salt                             | hash                                                             |
+-----------------------+----------------------------------+------------------------------------------------------------------+
| johnsmith@example.com | ^5@gVJN8>5p$67qXku2b6Oe6!#Z7Bd5c | 8993f6ad6e8539c0382ef40b3a320501d561d8e8eeceaaaeb59efcea6b7083b1 |
+-----------------------+----------------------------------+------------------------------------------------------------------+
```

## Validating Credentials
To check if a password for a given user is valid, use `pcs.CheckPassword`. It requires a user<br>
and the password you want to validate. It will pull the salt and hash from the database for the<br>
specified user, salt the given password, and check if the hashes match. If they do match, it will<br>
return `(true, nil)`. otherwise it will return `(false, nil)`.
```golang
func main() {
    // Returns true, nil 
    valid, err := pcs.CheckPassword("johnsmith@example.com", "password123")
    if err != nil{
        panic(err)
    }
	
    // Returns false, nil
    valid, err := pcs.CheckPassword("johnsmith@example.com", "notpassword123")
    if err != nil{
        panic(err)
    }
} 
```