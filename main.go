package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

type OpenAPIRequest struct {
	Env    string `json:"env"`
	APIKey string `json:"apiKey"`
}

type OpenAPIResponse struct {
	SessionKey string `json:"sessionKey"`
}

type OpenAPIErrorResponse struct {
	Error string `json:"error"`
}

type EnvironmentConfig struct {
	Name      string `json:"name"`
	PublicKey string `json:"publicKey"`
}

type AppConfig struct {
	Environments []EnvironmentConfig `json:"environments"`
}

var appConfig AppConfig

func main() {
	// Read the configuration file
	configFile, err := ioutil.ReadFile("config.json")
	if err != nil {
		log.Fatal("Failed to read configuration file:", err)
		return
	}

	// Parse the configuration
	if err := json.Unmarshal(configFile, &appConfig); err != nil {
		log.Fatal("Failed to parse configuration:", err)
		return
	}

	// router
	r := mux.NewRouter()
	r.HandleFunc("/hello", HelloHandler).Methods("GET")
	r.HandleFunc("/encrypt", OpenAPIHandler).Methods("POST")

	http.Handle("/", r)
	fmt.Println("Server is listening on :8080...")
	http.ListenAndServe(":8080", nil)
}

// show hello on browser
func HelloHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Hello, World!")
}

// openAPI encrypter handler
func OpenAPIHandler(w http.ResponseWriter, r *http.Request) {
	var request OpenAPIRequest

	// Decode the JSON request body into the OpenAPIRequest struct
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// create encoder
	encoder := json.NewEncoder(w)

	// Find the environment configuration for the requested environment
	var publicKey string
	for _, env := range appConfig.Environments {
		if env.Name == request.Env {
			publicKey = env.PublicKey
			break
		}
	}

	// check if public key is empty
	if publicKey == "" {
		openAPIInvalidEnvErrorResponse := OpenAPIErrorResponse{Error: "Invalid environment"}
		if err := encoder.Encode(openAPIInvalidEnvErrorResponse); err != nil {
			http.Error(w, "Invalid environment", http.StatusBadRequest)
			return
		}
		return
	}

	// Replace this logic with your own encrypted key generation
	sessionKey, err := EncryptAPIKey(publicKey, request.APIKey)
	if err != "" {
		fmt.Println("Error Encrytion of key:", err)
		openAPIErrorResponse := OpenAPIErrorResponse{Error: err}
		if err := encoder.Encode(openAPIErrorResponse); err != nil {
			http.Error(w, "Failed to send response", http.StatusInternalServerError)
			return
		}
		return
	}

	// Create the response
	response := OpenAPIResponse{SessionKey: sessionKey}

	// Encode and send the response as JSON
	w.Header().Set("Content-Type", "application/json")
	if err := encoder.Encode(response); err != nil {
		http.Error(w, "Failed to send response", http.StatusInternalServerError)
		return
	}
}

func EncryptAPIKey(envPublicKey, apiKey string) (string, string) {
	// Parse the base64-encoded public key bytes
	publicKeyBytes, err := base64.StdEncoding.DecodeString(envPublicKey)
	if err != nil {
		fmt.Println("Error decoding base64-encoded public key:", err)
		return "", "Error decoding base64-encoded public key"
	}

	// Parse the public key
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		fmt.Println("Error parsing public key:", err)
		return "", "Error parsing public key"
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		fmt.Println("Error converting to RSA public key")
		return "", "Error converting to RSA public key"
	}

	// Encrypt the access token using the public key
	encryptedToken, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPublicKey, []byte(apiKey))
	if err != nil {
		fmt.Println("Error encrypting access token:", err)
		return "", "Error encrypting access token"
	}

	// Encode the encrypted token as base64 before sending it
	base64EncryptedToken := base64.StdEncoding.EncodeToString(encryptedToken)

	// Add the encrypted token to the Authorization header
	encryptedKey := fmt.Sprintf("%v", base64EncryptedToken)

	return encryptedKey, ""
}
