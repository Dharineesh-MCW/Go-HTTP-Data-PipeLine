package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"time"
)

// API endpoints
const (
	loginURL  = "http://localhost:8080/login"
	serverURL = "http://localhost:8080/adduser"
)

// Struct for user data
type User struct {
	Name string `json:"name"`
	Role string `json:"role"`
	Age  int    `json:"age"`
}

// Struct for login credentials
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Global variable to store the JWT token
var jwtToken string

// Predefined roles
var roles = []string{"intern", "developer", "manager", "analyst"}

// Function to authenticate and get JWT token
func authenticate() error {
	creds := Credentials{
		Username: "admin",         // Change to valid username
		Password: "password123",   // Change to valid password
	}

	jsonData, err := json.Marshal(creds)
	if err != nil {
		return fmt.Errorf("error encoding JSON: %v", err)
	}

	resp, err := http.Post(loginURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to authenticate: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authentication failed: %s", resp.Status)
	}

	// Decode response to extract token
	var result map[string]string
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return fmt.Errorf("error decoding token response: %v", err)
	}

	jwtToken = result["token"]
	fmt.Println("Authentication successful. Token received.")
	return nil
}

// Function to send random user data via HTTP POST with authentication
func sendRandomUser() {
	for i := 0; i < 10; i++ {
		// Generate random user data
		user := User{
			Name: fmt.Sprintf("User%d", rand.Intn(10000)),
			Role: roles[rand.Intn(len(roles))],
			Age:  rand.Intn(40) + 18,
		}

		// Convert user struct to JSON
		jsonData, err := json.Marshal(user)
		if err != nil {
			log.Fatalf("Error encoding JSON: %v", err)
		}

		// Create HTTP request
		req, err := http.NewRequest("POST", serverURL, bytes.NewBuffer(jsonData))
		if err != nil {
			log.Printf("Failed to create request: %v", err)
			continue
		}

		// Set headers, including Authorization token
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+jwtToken)

		// Send HTTP request
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("Failed to send request: %v", err)
			continue
		}

		// Handle authentication failure (401 Unauthorized)
		if resp.StatusCode == http.StatusUnauthorized {
			fmt.Println("Token expired or invalid. Re-authenticating...", i+1)
			// if err := authenticate(); err != nil {
				// log.Fatalf("Re-authentication failed: %v", err)
			// } // Retry the same request
			time.Sleep(1 * time.Second)
			continue
		}

		fmt.Printf("Sent: %s   %v\n", jsonData, i+1)
		resp.Body.Close()

		// Wait before sending the next request
		time.Sleep(1 * time.Second)
	}
}

func main() {
	fmt.Println("Starting HTTP client...")

	// Authenticate before sending requests
	if err := authenticate(); err != nil {
		log.Fatalf("Authentication failed: %v", err)
	}

	// Start sending authenticated requests
	sendRandomUser()
}
