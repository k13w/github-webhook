package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

type GitHubWebhook struct {
	Ref        string `json:"ref"`
	Repository struct {
		Name string `json:"name"`
	} `json:"repository"`
}

func main() {
	// Get webhook secret from environment variable
	webhookSecret := os.Getenv("GITHUB_WEBHOOK_SECRET")
	if webhookSecret == "" {
		log.Fatal("GITHUB_WEBHOOK_SECRET environment variable is required")
	}

	// Get repository path from environment variable
	repoPath := os.Getenv("REPO_PATH")
	if repoPath == "" {
		log.Fatal("REPO_PATH environment variable is required")
	}

	http.HandleFunc("/webhook", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Verify GitHub signature
		signature := r.Header.Get("X-Hub-Signature-256")
		if signature == "" {
			http.Error(w, "No signature provided", http.StatusBadRequest)
			return
		}

		// Read request body
		payload, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Error reading request body", http.StatusBadRequest)
			return
		}

		// Verify signature
		if !verifySignature(payload, signature, webhookSecret) {
			http.Error(w, "Invalid signature", http.StatusUnauthorized)
			return
		}

		// Parse webhook payload
		var webhook GitHubWebhook
		if err := json.Unmarshal(payload, &webhook); err != nil {
			http.Error(w, "Error parsing webhook payload", http.StatusBadRequest)
			return
		}

		// Check if it's a push event
		eventType := r.Header.Get("X-GitHub-Event")
		if eventType == "push" {
			// Extract branch name from ref (e.g., "refs/heads/main" -> "main")
			branch := strings.TrimPrefix(webhook.Ref, "refs/heads/")

			// Update local repository
			if err := updateLocalRepo(repoPath, branch); err != nil {
				log.Printf("Error updating repository: %v", err)
				http.Error(w, "Error updating repository", http.StatusInternalServerError)
				return
			}
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Webhook processed successfully")
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting webhook server on port %s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}

func verifySignature(payload []byte, signature string, secret string) bool {
	// Remove "sha256=" prefix
	signature = strings.TrimPrefix(signature, "sha256=")

	// Calculate HMAC
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(payload)
	calculatedSignature := hex.EncodeToString(h.Sum(nil))

	return hmac.Equal([]byte(calculatedSignature), []byte(signature))
}

func updateLocalRepo(repoPath, branch string) error {
	// Change to repository directory
	if err := os.Chdir(repoPath); err != nil {
		return fmt.Errorf("error changing to repository directory: %v", err)
	}

	// Fetch latest changes
	fetchCmd := exec.Command("git", "fetch", "origin", branch)
	if err := fetchCmd.Run(); err != nil {
		return fmt.Errorf("error fetching changes: %v", err)
	}

	// Reset to origin/branch
	resetCmd := exec.Command("git", "reset", "--hard", fmt.Sprintf("origin/%s", branch))
	if err := resetCmd.Run(); err != nil {
		return fmt.Errorf("error resetting to origin/%s: %v", branch, err)
	}

	return nil
}
