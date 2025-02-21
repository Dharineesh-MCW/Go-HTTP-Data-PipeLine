package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/go-sql-driver/mysql"
)

// Secret key for signing JWT
var jwtKey = []byte("xxxx")

// Struct for request body
type User struct {
	Name string `json:"name"`
	Role string `json:"role"`
	Age  int    `json:"age"`
}

// JWT claims structure
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

var db *sql.DB

// Initialize MySQL connection
func initDB() {
	var err error
	dsn := "dharineesh:@tcp(x.x.x.x:3306)/mydb"
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal(err)
	}
}

// Generate JWT Token
func GenerateToken(username string) (string, error) {
	expirationTime := time.Now().Add(time.Second * 7) // Token expires in 1 hour
	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

// Login Handler (POST Request)
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var creds map[string]string
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Dummy authentication (Replace with actual DB verification)
	if creds["username"] != "admin" || creds["password"] != "password123" {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Generate token
	token, err := GenerateToken(creds["username"])
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	// Respond with the token
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

// Middleware to Authenticate Requests
func Authenticate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing token", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Continue to next handler
		next(w, r)
	}
}

// Function to handle POST requests
func addUserHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Insert data into MySQL database
	query := "INSERT INTO users (name, role, age) VALUES (?, ?, ?)"
	_, err = db.Exec(query, user.Name, user.Role, user.Age)
	if err != nil {
		log.Printf("Error executing query: %v", err)
		http.Error(w, "Error inserting data into DB", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("User added successfully"))
}

// Secure Handler
func SecureHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Authenticated user can access this!"))
}

// Main function to start the server
func main() {
	initDB()
	defer db.Close()

	http.HandleFunc("/adduser", Authenticate(addUserHandler))
	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/secure-data", Authenticate(SecureHandler))

	fmt.Println("Server is running on port 8080...")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal(err)
	}
}
