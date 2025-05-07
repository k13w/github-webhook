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
	"time"
)

type GitHubWebhook struct {
	Ref        string `json:"ref"`
	Repository struct {
		Name string `json:"name"`
	} `json:"repository"`
	Commits []struct {
		ID      string `json:"id"`
		Message string `json:"message"`
		Author  struct {
			Name string `json:"name"`
		} `json:"author"`
	} `json:"commits"`
}

func main() {
	// Configure log format
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.Println("Iniciando servidor de webhook...")

	// Get webhook secret from environment variable
	webhookSecret := os.Getenv("GITHUB_WEBHOOK_SECRET")
	if webhookSecret == "" {
		log.Fatal("GITHUB_WEBHOOK_SECRET environment variable is required")
	}
	log.Println("Webhook secret configurado com sucesso")

	// Get repository path from environment variable
	repoPath := os.Getenv("REPO_PATH")
	if repoPath == "" {
		log.Fatal("REPO_PATH environment variable is required")
	}
	log.Printf("Caminho do repositório configurado: %s", repoPath)

	http.HandleFunc("/webhook", func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()
		log.Printf("=== Nova requisição recebida em %s ===", startTime.Format("2006-01-02 15:04:05.000"))
		log.Printf("Headers recebidos:")
		for name, values := range r.Header {
			log.Printf("  %s: %s", name, strings.Join(values, ", "))
		}

		if r.Method != http.MethodPost {
			log.Printf("Método não permitido: %s", r.Method)
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		contentType := r.Header.Get("Content-Type")
		if !strings.Contains(contentType, "application/json") {
			log.Printf("Content-Type inválido: %s (esperado: application/json)", contentType)
			http.Error(w, "Content-Type must be application/json", http.StatusBadRequest)
			return
		}

		// Verify GitHub signature
		signature := r.Header.Get("X-Hub-Signature-256")
		if signature == "" {
			log.Println("Erro: Nenhuma assinatura fornecida no cabeçalho X-Hub-Signature-256")
			http.Error(w, "No signature provided", http.StatusBadRequest)
			return
		}
		log.Printf("Assinatura recebida: %s", signature)

		// Read request body
		payload, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("Erro ao ler o corpo da requisição: %v", err)
			http.Error(w, "Error reading request body", http.StatusBadRequest)
			return
		}
		log.Printf("Tamanho do payload recebido: %d bytes", len(payload))
		log.Printf("Primeiros 100 caracteres do payload: %s", string(payload[:min(100, len(payload))]))

		// Verify signature
		if !verifySignature(payload, signature, webhookSecret) {
			log.Println("Erro: Assinatura inválida")
			http.Error(w, "Invalid signature", http.StatusUnauthorized)
			return
		}
		log.Println("Assinatura verificada com sucesso")

		// Parse webhook payload
		var webhook GitHubWebhook
		if err := json.Unmarshal(payload, &webhook); err != nil {
			log.Printf("Erro ao decodificar o payload: %v", err)
			log.Printf("Payload completo recebido: %s", string(payload))
			http.Error(w, "Error parsing webhook payload", http.StatusBadRequest)
			return
		}

		// Check if it's a push event
		eventType := r.Header.Get("X-GitHub-Event")
		log.Printf("Tipo de evento: %s", eventType)

		if eventType == "push" {
			// Extract branch name from ref (e.g., "refs/heads/main" -> "main")
			branch := strings.TrimPrefix(webhook.Ref, "refs/heads/")
			log.Printf("Branch detectada: %s", branch)

			// Log commit information
			for _, commit := range webhook.Commits {
				log.Printf("Commit detectado - ID: %s, Autor: %s, Mensagem: %s",
					commit.ID[:7], commit.Author.Name, commit.Message)
			}

			// Update local repository
			log.Printf("Iniciando atualização do repositório local...")
			if err := updateLocalRepo(repoPath, branch); err != nil {
				log.Printf("Erro ao atualizar o repositório: %v", err)
				http.Error(w, "Error updating repository", http.StatusInternalServerError)
				return
			}
			log.Printf("Repositório atualizado com sucesso")
		}

		duration := time.Since(startTime)
		log.Printf("=== Requisição processada em %v ===\n", duration)

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Webhook processado com sucesso em %v", duration)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Servidor webhook iniciado na porta %s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}

func verifySignature(payload []byte, signature string, secret string) bool {
	// Remove "sha256=" prefix
	signature = strings.TrimPrefix(signature, "sha256=")
	log.Printf("Verificando assinatura (sem prefixo): %s", signature)

	// Calculate HMAC
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(payload)
	calculatedSignature := hex.EncodeToString(h.Sum(nil))
	log.Printf("Assinatura calculada: %s", calculatedSignature)

	return hmac.Equal([]byte(calculatedSignature), []byte(signature))
}

func updateLocalRepo(repoPath, branch string) error {
	log.Printf("Mudando para o diretório: %s", repoPath)
	// Change to repository directory
	if err := os.Chdir(repoPath); err != nil {
		return fmt.Errorf("erro ao mudar para o diretório do repositório: %v", err)
	}

	// Fetch latest changes
	log.Printf("Executando git fetch origin %s", branch)
	fetchCmd := exec.Command("git", "fetch", "origin", branch)
	fetchOutput, err := fetchCmd.CombinedOutput()
	if err != nil {
		log.Printf("Erro no fetch. Saída do comando:\n%s", string(fetchOutput))
		return fmt.Errorf("erro ao buscar alterações: %v", err)
	}
	log.Printf("Fetch concluído com sucesso. Saída:\n%s", string(fetchOutput))

	// Pull latest changes
	log.Printf("Executando git pull origin %s", branch)
	pullCmd := exec.Command("git", "pull", "origin", branch)
	pullOutput, err := pullCmd.CombinedOutput()
	if err != nil {
		log.Printf("Erro no pull. Saída do comando:\n%s", string(pullOutput))
		return fmt.Errorf("erro ao fazer pull: %v", err)
	}
	log.Printf("Pull concluído com sucesso. Saída:\n%s", string(pullOutput))

	// Reset to origin/branch
	log.Printf("Executando git reset --hard origin/%s", branch)
	resetCmd := exec.Command("git", "reset", "--hard", fmt.Sprintf("origin/%s", branch))
	resetOutput, err := resetCmd.CombinedOutput()
	if err != nil {
		log.Printf("Erro no reset. Saída do comando:\n%s", string(resetOutput))
		return fmt.Errorf("erro ao resetar para origin/%s: %v", branch, err)
	}
	log.Printf("Reset concluído com sucesso. Saída:\n%s", string(resetOutput))

	// Mostrar status final
	log.Printf("Executando git status para verificar estado final")
	statusCmd := exec.Command("git", "status")
	statusOutput, err := statusCmd.CombinedOutput()
	if err != nil {
		log.Printf("Erro ao verificar status. Saída do comando:\n%s", string(statusOutput))
	} else {
		log.Printf("Status final do repositório:\n%s", string(statusOutput))
	}

	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
