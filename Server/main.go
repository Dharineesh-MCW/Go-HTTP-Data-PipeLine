package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

var jwtKey []byte
var dbLogin *sql.DB
var dbMyDB *sql.DB
var serverID string

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type User struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	Age        int    `json:"age"`
	YearsOfExp int    `json:"yearsofexp"`
	Salary     int    `json:"salary"`
}

type UserData struct {
	Name              string `json:"name"`
	Age               int    `json:"age"`
	YearsOfExperience int    `json:"yearsofexp"`
	Salary            int    `json:"salary"`
}

type Employee struct {
	ID         int `json:"id"`
	YearsOfExp int `json:"yearsofexp"`
	Salary     int `json:"salary"`
}

func loadEnv() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	jwtKey = []byte(os.Getenv("JWT_SECRET"))
	serverID = os.Getenv("SERVER_ID") // Load server ID
	if len(jwtKey) == 0 {
		log.Fatal("Missing JWT_SECRET in .env file")
	}
	if serverID == "" {
		log.Fatal("Missing SERVER_ID in .env file")
	}
}

func connectDBs() {
	var err error
	dbLogin, err = sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/logincredentials",
		os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT")))
	if err != nil {
		log.Fatal("Error connecting to login DB:", err)
	}
	dbMyDB, err = sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/mydb",
		os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT")))
	if err != nil {
		log.Fatal("Error connecting to main DB:", err)
	}
	if err = dbLogin.Ping(); err != nil {
		log.Fatal("Login DB not reachable:", err)
	}
	if err = dbMyDB.Ping(); err != nil {
		log.Fatal("Main DB not reachable:", err)
	}
	fmt.Println("Connected to both databases successfully!")
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		logRequest(r, http.StatusMethodNotAllowed)
		return
	}

	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	var storedHashedPassword string
	err = dbLogin.QueryRow("SELECT password FROM users WHERE username = ?", credentials.Username).Scan(&storedHashedPassword)

	if err == sql.ErrNoRows {
		// New user: hash password and insert into DB
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(credentials.Password), bcrypt.DefaultCost)
		_, err = dbLogin.Exec("INSERT INTO users (username, password) VALUES (?, ?)", credentials.Username, string(hashedPassword))
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		storedHashedPassword = string(hashedPassword)
	} else if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Check password
	err = bcrypt.CompareHashAndPassword([]byte(storedHashedPassword), []byte(credentials.Password))
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Generate JWT token
	expirationTime := time.Now().Add(1 * time.Hour)
	claims := &Claims{
		Username: credentials.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Could not generate token", http.StatusInternalServerError)
		return
	}

	serverID := os.Getenv("SERVER_ID") // Set SERVER_ID=1 or 2 in .env

	json.NewEncoder(w).Encode(map[string]string{
		"token":     tokenStr,
		"server_id": serverID,
	})
	logRequest(r, http.StatusOK)
}

func getClientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ips := strings.Split(forwarded, ",")
		return strings.TrimSpace(ips[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Logging format function
func logRequest(r *http.Request, statusCode int) {
	clientIP := getClientIP(r)
	timestamp := time.Now().Format("02/Jan/2006 15:04:05")
	log.Printf("%s - - [%s] \"%s %s %s\" %d",
		clientIP, timestamp, r.Method, r.URL.Path, r.Proto, statusCode)
}

// Catch-all Handler (For invalid routes)
func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Bad Request", http.StatusBadRequest)
	logRequest(r, http.StatusBadRequest)
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if len(tokenString) < 8 {
			log.Println("No Authorization token provided.")
			http.Error(w, "Unauthorized: No token provided (1)", http.StatusUnauthorized)
			return
		}

		tokenString = tokenString[7:] // Remove "Bearer "
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			log.Println("Invalid JWT token:", err)
			http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

func AddEmployeeHandler(w http.ResponseWriter, r *http.Request) {
	var user UserData
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	_, err = dbMyDB.Exec("INSERT INTO employee (name, age, yearsofexp, salary) VALUES (?, ?, ?, ?)", user.Name, user.Age, user.YearsOfExperience, user.Salary)
	if err != nil {
		http.Error(w, "Error inserting data", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Values added successfully"))
	logRequest(r, http.StatusOK)
	
}

func getUsersHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := dbMyDB.Query("SELECT id, name, age, yearsofexp, salary FROM employee")
	if err != nil {
		log.Println("Database query failed:", err)
		http.Error(w, "Failed to fetch users", http.StatusInternalServerError)
		logRequest(r, http.StatusMethodNotAllowed)
		return
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Name, &user.Age, &user.YearsOfExp, &user.Salary); err != nil {
			log.Println("Error scanning user row:", err)
			continue
		}
		users = append(users, user)
	}

	if len(users) == 0 {
		log.Println(" No users found in the database.")
		http.Error(w, "No users found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
	logRequest(r, http.StatusOK)
	
}

func fetchEmployees(db *sql.DB) ([]Employee, error) {
	rows, err := db.Query("SELECT id, yearsofexp, salary FROM employee")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var employees []Employee
	for rows.Next() {
		var emp Employee
		if err := rows.Scan(&emp.ID, &emp.YearsOfExp, &emp.Salary); err != nil {
			return nil, err
		}
		employees = append(employees, emp)
	}
	return employees, nil
}

func updateSalary(db *sql.DB, id int, newSalary int) error {
	_, err := db.Exec("UPDATE employee SET salary = ? WHERE id = ?", newSalary, id)
	return err
}

func processSalaryHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("mysql", "dharineesh:Admin@1234@tcp(192.168.6.3:3306)/mydb")
	if err != nil {
		http.Error(w, "DB connection error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	employees, err := fetchEmployees(db)
	if err != nil {
		http.Error(w, "Error fetching employees", http.StatusInternalServerError)
		return
	}

	for _, emp := range employees {
		jsonData, _ := json.Marshal(emp)

		resp, err := http.Post("http://192.168.6.19:8080/update-salary", "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			fmt.Printf("Failed to send data for Employee %d\n", emp.ID)
			continue
		}
		defer resp.Body.Close()

		var result struct {
			NewSalary int `json:"new_salary"`
		}
		json.NewDecoder(resp.Body).Decode(&result)

		updateSalary(db, emp.ID, result.NewSalary)
		logRequest(r, http.StatusOK)
		// fmt.Printf("Updated salary for Employee %d to %d\n", emp.ID, result.NewSalary)
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Salary processing completed"))
}

func main() {

	loadEnv()
	connectDBs()
	defer dbLogin.Close()
	defer dbMyDB.Close()

	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/", notFoundHandler)
	http.HandleFunc("/getemployees", authMiddleware(getUsersHandler))
	http.HandleFunc("/addemployee", authMiddleware(AddEmployeeHandler))
	http.HandleFunc("/processsalary", authMiddleware(processSalaryHandler))

	fmt.Printf("Server %s running on :8080\n", serverID)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
