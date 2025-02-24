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
	"golang.org/x/crypto/bcrypt"
	_ "github.com/go-sql-driver/mysql"
)

// Secret key for signing JWT
var jwtKey = []byte("")

// Structs
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type UserData struct {
	Name string `json:"name"`
	Role string `json:"role"`
	Age  int    `json:"age"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

var usersDB, mydb *sql.DB

// Initialize MySQL connections
func initDB() {
	var err error

	usersDB, err = sql.Open("mysql", "dharineesh:@tcp(192.168.x.x:3306)/logincredentials")
	if err != nil {
		log.Fatal("Users DB connection error:", err)
	}

	mydb, err = sql.Open("mysql", "dharineesh:@tcp(192.168.x.x:3306)/mydb")
	if err != nil {
		log.Fatal("MyDB connection error:", err)
	}
}

// Password hashing function
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// Password verification function
func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Generate JWT Token
func GenerateToken(username string) (string, error) {
	expirationTime := time.Now().Add(time.Hour * 1)
	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

// Signup Handler (POST Request)
func SignupHandler(w http.ResponseWriter, r *http.Request) {
	var creds User
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Hash the password
	hashedPassword, err := hashPassword(creds.Password)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	// Store in users DB
	_, err = usersDB.Exec("INSERT INTO users (username, password) VALUES (?, ?)", creds.Username, hashedPassword)
	if err != nil {
		http.Error(w, "Error storing user", http.StatusInternalServerError)
		fmt.Print(err)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("User registered successfully"))
}

// Login Handler (POST Request)
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var creds User
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Fetch hashed password from DB
	var storedPassword string
	err = usersDB.QueryRow("SELECT password FROM users WHERE username = ?", creds.Username).Scan(&storedPassword)
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Compare passwords
	if !checkPasswordHash(creds.Password, storedPassword) {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Generate token
	token, err := GenerateToken(creds.Username)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

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

		next(w, r)
	}
}

// Add User Handler (JWT protected, inserts into `mydb`)
func AddUserHandler(w http.ResponseWriter, r *http.Request) {
	var user UserData
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	_, err = mydb.Exec("INSERT INTO users (name, role, age) VALUES (?, ?, ?)", user.Name, user.Role, user.Age)
	if err != nil {
		http.Error(w, "Error inserting data", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("User added successfully"))
}

func main() {
	initDB()
	defer usersDB.Close()
	defer mydb.Close()

	http.HandleFunc("/signup", SignupHandler)
	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/adduser", Authenticate(AddUserHandler))

	fmt.Println("Server is running on port 8080...")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal(err)
	}
}
