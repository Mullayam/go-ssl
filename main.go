package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/acme"
)

const (
	// ACME directory URL (Use Boulder  Server)
	acmeDirectoryURL = "https://localhost:4001/directory"

	// Challenge directory for HTTP-01 validation
	challengePath = "/.well-known/acme-challenge/"
)

// Generate RSA Private Key
func generatePrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// Register a new ACME account
func registerAccount(client *acme.Client) (*acme.Account, error) {
	account := &acme.Account{}
	account, err := client.Register(context.Background(), account, nil)
	if err != nil {
		return nil, err
	}
	fmt.Println("Registered ACME Account:", account.URI)
	return account, nil
}

func requestCertificate(client *acme.Client, domain string) ([]byte, []byte, error) {
	privKey, err := generatePrivateKey()
	if err != nil {
		return nil, nil, err
	}

	// Create CSR (Certificate Signing Request)
	csr := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: domain,
		},
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csr, privKey)
	if err != nil {
		return nil, nil, err
	}

	// Encode CSR in PEM format
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	// Request certificate
	cert, certURL, err := client.CreateOrderCert(context.Background(), &acme.Order{
		Identifiers: []acme.Identifier{{Type: "dns", Value: domain}},
	}, csrPEM, true)
	if err != nil {
		return nil, nil, err
	}

	fmt.Println("Certificate URL:", certURL)
	return cert, csrPEM, nil
}

func startHTTPServer() {
	http.HandleFunc(challengePath, func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Path[len(challengePath):]
		response, err := ioutil.ReadFile("/tmp/" + token)
		if err != nil {
			http.Error(w, "Challenge Not Found", http.StatusNotFound)
			return
		}
		w.Write(response)
	})
	go http.ListenAndServe(":80", nil)
}

// Handle HTTP-01 Challenge
func handleHTTPChallenge(client *acme.Client, authz *acme.Authorization) error {
	for _, challenge := range authz.Challenges {
		if challenge.Type == "http-01" {
			fmt.Println("Serving HTTP-01 challenge for", authz.Identifier.Value)

			// Write challenge response file
			ioutil.WriteFile("/tmp/"+challenge.Token, []byte(challenge.KeyAuthorization), 0644)

			// Inform ACME server that challenge is ready
			_, err := client.Accept(context.Background(), challenge)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
func autoRenew(client *acme.Client, domain string) {
	for {
		time.Sleep(30 * 24 * time.Hour) // Check every 30 days

		cert, err := requestCertificate(client, domain)
		if err != nil {
			log.Println("Renewal failed:", err)
			continue
		}

		fmt.Println("Certificate renewed successfully:", string(cert))
	}
}
func enableOCSP(certPath, keyPath string) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Fatal("Failed to load cert:", err)
	}

	// Enable OCSP
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		OCSPStapling: true,
	}

	listener, err := net.Listen("tcp", ":443")
	if err != nil {
		log.Fatal(err)
	}

	server := &http.Server{
		TLSConfig: config,
	}

	fmt.Println("OCSP stapling enabled on port 443")
	server.Serve(listener)
}
func main() {
	// Start HTTP server for challenges
	startHTTPServer()
	// Initialize ACME client
	client := &acme.Client{
		DirectoryURL: acmeDirectoryURL,
		Key:          nil, // Generate or load an ACME account key
	}

	// Register ACME Account
	_, err := registerAccount(client)
	if err != nil {
		log.Fatalf("Failed to register ACME account: %v", err)
	}

	// Request SSL Certificate
	domain := "example.com"
	cert, csr, err := requestCertificate(client, domain)
	if err != nil {
		log.Fatalf("Failed to get certificate: %v", err)
	}

	fmt.Println("Certificate:", string(cert))
	fmt.Println("CSR:", string(csr))
}
