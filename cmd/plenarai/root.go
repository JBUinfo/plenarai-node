package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"

	"github.com/plenarai/cli/internal/auth"
	"github.com/plenarai/cli/internal/config"
	"github.com/plenarai/cli/internal/inference"
	"github.com/plenarai/cli/internal/llamacpp"
	"github.com/plenarai/cli/internal/node"
	"github.com/plenarai/cli/internal/questioner"
	"github.com/plenarai/cli/internal/security"
	"github.com/plenarai/cli/internal/setup"
	"github.com/plenarai/cli/internal/tui"
	"github.com/plenarai/cli/internal/update"
	"github.com/plenarai/cli/logger"
)

var verbose bool

var rootCmd = &cobra.Command{
	Use:   "plenarai",
	Short: "PlenarAI - Independent AI Marketplace",
	Long:  "CLI client for the PlenarAI platform. Ask questions or run as a node to earn credits.",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		logger.Init(verbose)
		update.CleanupOldBinary()
		return config.ValidateServerURL()
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		return tui.Run()
	},
}

var (
	promptFile          string
	modelName           string
	modelPath           string
	contextWindowTokens int
	scoreOnly           bool
	minNodeCost         float64
	ollamaURL           string
	stakeAmount         float64
	noUI                bool
	setupEngine         string
	setupModelPath      string
	setupModelURL       string
)

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")

	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(logoutCmd)
	rootCmd.AddCommand(registerCmd)
	rootCmd.AddCommand(nodeCmd)
	rootCmd.AddCommand(askCmd)
	rootCmd.AddCommand(setupCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(scorerRegisterCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(updateCmd)
	askCmd.Flags().StringVar(&askNodeID, "node-id", "", "send only to this provider UUID")
	askCmd.Flags().Float64Var(&askCost, "cost", 1, "question price in credits; must meet the chosen provider minimum")
	askCmd.Flags().StringVar(&askMode, "mode", "directed", "directed (requires --node-id) or evaluated (explicit optional evaluation)")

	nodeCmd.Flags().StringVarP(&promptFile, "prompt", "p", "", "path to custom prompt file")
	nodeCmd.Flags().StringVarP(&modelName, "model", "m", "llama3", "ollama model to use (legacy --engine ollama)")
	nodeCmd.Flags().StringVar(&modelPath, "model-path", "", "path to a custom GGUF model file (uses the bundled llama.cpp engine)")
	nodeCmd.Flags().IntVar(&contextWindowTokens, "context-window-tokens", inference.DefaultContextWindowTokens, "local llama.cpp context window (4096-32768; evaluated chat may need 8192)")
	nodeCmd.Flags().BoolVar(&scoreOnly, "score-only", false, "run as judge only: score other nodes' answers, never respond")
	nodeCmd.Flags().Float64Var(&minNodeCost, "min-cost", 0, "minimum question price this node will answer")
	setupCmd.Flags().StringVar(&setupEngine, "engine", "llama", "inference engine: llama (default) or ollama")
	setupCmd.Flags().StringVar(&setupModelPath, "model-path", "", "use an existing GGUF file instead of downloading the default model")
	setupCmd.Flags().StringVar(&setupModelURL, "model-url", "", "download a specific GGUF URL instead of the default model")
	nodeCmd.Flags().StringVar(&ollamaURL, "ollama-url", "http://localhost:11434", "ollama API URL")
	nodeCmd.Flags().Float64VarP(&stakeAmount, "stake", "s", 0, "deposit credits as stake before connecting (skipped if already staked)")
	setupCmd.Flags().BoolVar(&noUI, "no-ui", false, "disable progress bars (useful for logs/CI)")
}

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with the PlenarAI server",
	RunE: func(cmd *cobra.Command, args []string) error {
		email, password, err := promptCredentials()
		if err != nil {
			return err
		}
		return doLogin(email, password)
	},
}

func promptCredentials() (string, string, error) {
	var email string
	fmt.Print("Email: ")
	fmt.Scanln(&email)

	fmt.Print("Password: ")
	pw, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", "", fmt.Errorf("failed to read password: %w", err)
	}
	return email, string(pw), nil
}

func doLogin(email, password string) error {
	tokens, err := auth.Login(email, password)
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}
	if err := auth.SaveTokens(tokens); err != nil {
		return fmt.Errorf("failed to save credentials: %w", err)
	}
	fmt.Println("Login successful.")
	return nil
}

var nodeCmd = &cobra.Command{
	Use:   "node",
	Short: "Start as a responder node and earn credits",
	RunE: func(cmd *cobra.Command, args []string) error {
		if contextWindowTokens < inference.DefaultContextWindowTokens || contextWindowTokens > inference.MaxContextWindowTokens {
			return fmt.Errorf("context-window-tokens must be between %d and %d", inference.DefaultContextWindowTokens, inference.MaxContextWindowTokens)
		}
		auth.LoadConfig()

		finalModel := modelName
		if !cmd.Flags().Changed("model") {
			if saved := viper.GetString("ollama.model"); saved != "" {
				finalModel = saved
			}
		}
		finalOllamaURL := ollamaURL
		if !cmd.Flags().Changed("ollama-url") {
			if saved := viper.GetString("ollama.url"); saved != "" {
				finalOllamaURL = saved
			}
		}
		finalModelPath := modelPath
		if !cmd.Flags().Changed("model-path") {
			if saved := viper.GetString("llama.model_path"); saved != "" {
				finalModelPath = saved
			}
		}
		if finalModelPath == "" && contextWindowTokens != inference.DefaultContextWindowTokens {
			return fmt.Errorf("generation limits require a local GGUF model")
		}

		// Validate local limits before any optional stake deposit.
		if stakeAmount > 0 {
			if err := depositStake(stakeAmount); err != nil {
				return err
			}
		}

		return node.Run(node.Config{
			PromptFile:          promptFile,
			ConfigDir:           auth.ConfigDir(),
			Model:               finalModel,
			OllamaURL:           finalOllamaURL,
			ModelPath:           finalModelPath,
			ContextWindowTokens: contextWindowTokens,
			ScoreOnly:           scoreOnly,
		})
	},
}

func depositStake(amount float64) error {
	header, err := auth.AuthHeader()
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]float64{"amount": amount})
	req, _ := http.NewRequest(http.MethodPost, config.ServerURL+"/v0/node/stake", bytes.NewReader(body))
	req.Header.Set("Authorization", header)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("stake request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var errResp map[string]string
		json.NewDecoder(resp.Body).Decode(&errResp)
		return fmt.Errorf("stake failed: %s", errResp["error"])
	}
	fmt.Printf("Staked %.1f credits.\n", amount)
	return nil
}

var scorerRegisterCmd = &cobra.Command{
	Use:   "scorer-register",
	Short: "Register this account as a scorer node (eligibility rules apply)",
	RunE: func(cmd *cobra.Command, args []string) error {
		auth.LoadConfig()

		header, err := auth.AuthHeader()
		if err != nil {
			return err
		}

		// Show requirements vs current status when the server exposes them.
		var reqs struct {
			MinAnswered int     `json:"min_answered"`
			MinStake    float64 `json:"min_stake"`
		}
		var profile struct {
			StakeAmount   float64 `json:"stake_amount"`
			TotalAnswered int     `json:"total_answered"`
		}
		haveReqs := apiGet(header, "/v0/node/scorer-requirements", &reqs) == nil
		haveProfile := apiGet(header, "/v0/node/stake", &profile) == nil
		if haveReqs && haveProfile {
			fmt.Println("Scorer requirements:")
			printRequirement("Answered questions", float64(profile.TotalAnswered), float64(reqs.MinAnswered))
			printRequirement("Stake (credits)", profile.StakeAmount, reqs.MinStake)
			fmt.Println()
		}

		req, _ := http.NewRequest(http.MethodPost, config.ServerURL+"/v0/node/register-scorer", nil)
		req.Header.Set("Authorization", header)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("scorer registration failed: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			var errResp map[string]string
			json.NewDecoder(resp.Body).Decode(&errResp)
			return fmt.Errorf("scorer registration failed: %s", errResp["error"])
		}
		fmt.Println("Registered as a scorer node.")
		return nil
	},
}

// printRequirement renders one eligibility line with a check or cross mark.
func printRequirement(name string, current, required float64) {
	mark := "✓"
	if current < required {
		mark = "✗"
	}
	fmt.Printf("  %s %-20s %10.0f / %.0f\n", mark, name+":", current, required)
}

var askCmd = &cobra.Command{
	Use:   "ask [question]",
	Short: "Ask a chosen provider, or opt into evaluated mode",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if askMode != "directed" && askMode != "evaluated" {
			return fmt.Errorf("--mode must be directed or evaluated")
		}
		if askMode == "directed" && askNodeID == "" {
			return fmt.Errorf("choose a provider with --node-id; discover providers with plenarai providers, or explicitly use --mode evaluated")
		}
		if askMode == "evaluated" && askNodeID != "" {
			return fmt.Errorf("--node-id cannot be combined with --mode evaluated")
		}
		question := strings.Join(args, " ")

		fmt.Println("Note: responder nodes read your question to answer it (they never learn who asked).")
		fmt.Println("Avoid including personal data or secrets in the question text.")
		result, err := questioner.Ask(question, askNodeID, askCost)
		if err != nil {
			return fmt.Errorf("ask failed: %w", err)
		}

		fmt.Printf("Question submitted (ID: %s)\n", result.QuestionID)
		if askNodeID != "" {
			fmt.Printf("Directed to node %s (queue position: %d; voting and judge bypassed)\n", askNodeID, result.QueuePosition)
		}
		fmt.Println("Waiting for response...")

		for i := 0; i < 30; i++ {
			time.Sleep(2 * time.Second)
			poll, err := questioner.PollResult(result.QuestionID)
			if err != nil {
				continue
			}
			if poll.Status == "completed" {
				fmt.Printf("\nAnswer (score %.2f):\n%s\n", poll.Score, poll.Answer)
				return nil
			}
			if poll.Status == "failed" {
				fmt.Println("\nQuestion failed - no responses received.")
				return nil
			}
			fmt.Print(".")
		}
		fmt.Println("\nTimeout waiting for response. Check later with the question ID.")
		return nil
	},
}

var askNodeID string
var askMode string
var askCost float64

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Clear saved credentials",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := auth.Logout(); err != nil {
			return fmt.Errorf("logout failed: %w", err)
		}
		fmt.Println("Logged out.")
		return nil
	},
}

var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Create a new account on the PlenarAI server",
	RunE: func(cmd *cobra.Command, args []string) error {
		email, password, err := promptCredentials()
		if err != nil {
			return err
		}
		if utf8.RuneCountInString(password) < 8 {
			return fmt.Errorf("password must be at least 8 characters")
		}

		fmt.Println("Read the terms and privacy notice at https://plenarai.com/terms and https://plenarai.com/privacy")
		fmt.Print("I confirm I am at least 18 years old (yes/no): ")
		var adultReply string
		if _, err := fmt.Scanln(&adultReply); err != nil {
			return fmt.Errorf("failed to read age confirmation: %w", err)
		}
		if !strings.EqualFold(adultReply, "yes") {
			return fmt.Errorf("registration is restricted to people aged 18 or older")
		}
		body, _ := json.Marshal(map[string]any{"email": email, "password": password, "adult_attested": true})
		resp, err := http.Post(config.ServerURL+"/v0/auth/register", "application/json", bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("connection failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusCreated {
			var failure struct {
				Error string `json:"error"`
			}
			if json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&failure) == nil && failure.Error != "" {
				return fmt.Errorf("registration failed (status %d): %s", resp.StatusCode, failure.Error)
			}
			return fmt.Errorf("registration failed (status %d)", resp.StatusCode)
		}

		fmt.Println("Registration successful.")
		return doLogin(email, password)
	},
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show your current account, model, stake and earnings",
	RunE: func(cmd *cobra.Command, args []string) error {
		auth.LoadConfig()

		header, err := auth.AuthHeader()
		if err != nil {
			fmt.Println("Not logged in. Use 'plenarai login' first.")
			return nil
		}

		// User
		var me struct {
			Email string `json:"email"`
			Role  string `json:"role"`
		}
		if err := apiGet(header, "/v0/users/me", &me); err == nil {
			fmt.Printf("User:    %s (%s)\n", me.Email, me.Role)
		}

		// Wallet
		var wallet struct {
			BalanceCredits float64 `json:"balance_credits"`
		}
		if err := apiGet(header, "/v0/wallet", &wallet); err == nil {
			fmt.Printf("Balance: %.4f credits\n", wallet.BalanceCredits)
		}

		// Stake / Node profile
		var stake struct {
			StakeAmount   float64 `json:"stake_amount"`
			IsSuspended   bool    `json:"is_suspended"`
			Earnings      float64 `json:"earnings"`
			TotalAnswered int     `json:"total_answered"`
			TotalWon      int     `json:"total_won"`
			IsScorer      bool    `json:"is_scorer"`
		}
		if err := apiGet(header, "/v0/node/stake", &stake); err == nil {
			fmt.Printf("Stake:   %.1f credits", stake.StakeAmount)
			if stake.IsSuspended {
				fmt.Print(" (SUSPENDED)")
			}
			fmt.Println()
			fmt.Printf("Answered: %d   Won: %d\n", stake.TotalAnswered, stake.TotalWon)
			fmt.Printf("Earnings: %.4f credits\n", stake.Earnings)
			scorerState := "no"
			if stake.IsScorer {
				scorerState = "yes"
			}
			fmt.Printf("Scorer:  %s\n", scorerState)
		}

		// Selected model
		model := viper.GetString("ollama.model")
		if model == "" {
			model = "(not configured - run 'plenarai setup')"
		}
		fmt.Printf("Model:   %s\n", model)

		fmt.Printf("Server:  %s\n", config.ServerURL)
		return nil
	},
}

func apiGet(authHeader, path string, out interface{}) error {
	req, _ := http.NewRequest(http.MethodGet, config.ServerURL+path, nil)
	req.Header.Set("Authorization", authHeader)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Install the local AI engine (llama.cpp) and a model to run as a node",
	RunE: func(cmd *cobra.Command, args []string) error {
		auth.LoadConfig() // load existing config so we don't overwrite tokens

		if noUI {
			setup.DefaultProgressMode = setup.ProgressQuiet
		}

		fmt.Println("PlenarAI Node Setup")
		fmt.Println("===================")
		fmt.Println()

		if setupEngine == "ollama" {
			return setupOllama()
		}
		return setupLlama()
	},
}

// setupLlama installs the bundled llama.cpp engine and a GGUF model.
func setupLlama() error {
	binDir := filepath.Join(auth.ConfigDir(), "bin")
	modelsDir := filepath.Join(auth.ConfigDir(), "models")

	if err := llamacpp.Install(binDir); err != nil {
		return err
	}

	modelPath := setupModelPath
	if modelPath == "" {
		if saved := viper.GetString("llama.model_path"); saved != "" && fileExists(saved) {
			fmt.Printf("Using existing model: %s\n", saved)
			modelPath = saved
		}
	}
	if modelPath == "" {
		url := llamacpp.DefaultModelURL
		if setupModelURL != "" {
			url = setupModelURL
		}
		modelPath = filepath.Join(modelsDir, path.Base(url))
		if err := llamacpp.DownloadModel(url, modelPath); err != nil {
			return err
		}
	}
	if !fileExists(modelPath) {
		return fmt.Errorf("model file not found: %s", modelPath)
	}

	viper.Set("engine", "llama")
	viper.Set("llama.server_bin", llamacpp.ServerPath(binDir))
	viper.Set("llama.model_path", modelPath)
	viper.Set("ollama.model", "")
	viper.Set("ollama.url", "")
	if err := auth.SaveConfig(); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	// Verify end to end before declaring success.
	fmt.Println("Verifying the engine starts...")
	srv, err := inference.Start(llamacpp.ServerPath(binDir), modelPath)
	if err != nil {
		return fmt.Errorf("engine verification failed: %w", err)
	}
	srv.Stop()

	fmt.Println()
	fmt.Printf("Setup complete. Engine: llama.cpp %s. Model: %s\n", llamacpp.PinnedVersion, filepath.Base(modelPath))
	fmt.Println("Run 'plenarai node --stake 5' to start earning credits.")
	fmt.Println("To use your own fine-tune later: plenarai node --model-path /path/to/model.gguf")
	return nil
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// setupOllama is the legacy flow for operators who already run Ollama.
func setupOllama() error {
	if !setup.IsOllamaInstalled() {
		fmt.Println("Ollama is not installed.")
		fmt.Print("Install Ollama automatically now? [Y/n]: ")
		var answer string
		fmt.Scanln(&answer)
		if answer == "" || strings.ToLower(answer) == "y" {
			fmt.Println("Installing ollama...")
			if err := setup.TryInstall(); err != nil {
				fmt.Println("Auto-install failed. Manual install:")
				fmt.Println("  " + setup.InstallInstructions())
				return err
			}
			fmt.Println("Ollama installed.")
		} else {
			fmt.Println("Manual install:")
			fmt.Println("  " + setup.InstallInstructions())
			return nil
		}
	} else {
		fmt.Println("Ollama is installed.")
	}

	ollamaURLLocal := viper.GetString("ollama-url")
	if ollamaURLLocal == "" {
		ollamaURLLocal = setup.DefaultOllamaURL
	}

	if !setup.IsOllamaRunning(ollamaURLLocal) {
		fmt.Println()
		fmt.Println("Ollama service is not running.")
		fmt.Println("Start it with: ollama serve")
		return fmt.Errorf("ollama not reachable at %s", ollamaURLLocal)
	}

	installed, err := setup.ListModels(ollamaURLLocal)
	if err != nil {
		return fmt.Errorf("could not list models: %w", err)
	}

	fmt.Println()
	if len(installed) > 0 {
		fmt.Println("Installed models:")
		for i, m := range installed {
			fmt.Printf("  %d) %s (%.1f MB)\n", i+1, m.Name, float64(m.Size)/1024/1024)
		}
	} else {
		fmt.Println("No models installed yet.")
	}

	fmt.Println()
	fmt.Println("Suggested models for PlenarAI:")
	for i, m := range setup.SuggestedModels() {
		fmt.Printf("  %c) %s\n", 'a'+i, m)
	}

	fmt.Println()
	fmt.Print("Choose a model to use (number, letter, or custom name): ")
	var choice string
	fmt.Scanln(&choice)

	var selected string
	if n, err := strconv.Atoi(choice); err == nil && n >= 1 && n <= len(installed) {
		selected = installed[n-1].Name
	} else if len(choice) == 1 && choice[0] >= 'a' && int(choice[0]-'a') < len(setup.SuggestedModels()) {
		selected = setup.SuggestedModels()[choice[0]-'a']
	} else {
		selected = choice
	}

	if selected == "" {
		return fmt.Errorf("no model selected")
	}

	alreadyInstalled := false
	for _, m := range installed {
		if m.Name == selected || strings.HasPrefix(m.Name, selected+":") {
			alreadyInstalled = true
			selected = m.Name
			break
		}
	}

	if !alreadyInstalled {
		fmt.Printf("Downloading model %s...\n", selected)
		if err := setup.PullModel(ollamaURLLocal, selected); err != nil {
			return fmt.Errorf("download failed: %w", err)
		}
	}

	viper.Set("engine", "ollama")
	viper.Set("ollama.model", selected)
	viper.Set("ollama.url", ollamaURLLocal)
	viper.Set("llama.model_path", "")
	if err := auth.SaveConfig(); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Println()
	fmt.Printf("Setup complete. Model '%s' configured.\n", selected)
	fmt.Println("Run 'plenarai node --stake 5' to start earning credits.")
	return nil
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show the CLI version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("plenarai %s\n", config.Version)
		if security.RuntimeSecretAvailable() {
			fmt.Println("runtime/secret: enabled (experimental)")
		} else {
			fmt.Println("runtime/secret: unavailable in this build")
		}
		if tag, ok := update.CheckAvailable(); ok {
			fmt.Printf("New version available: %s. Run 'plenarai update'.\n", tag)
		}
	},
}

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update the CLI to the latest release",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Checking for updates...")
		msg, err := update.SelfUpdate()
		if err != nil {
			return fmt.Errorf("update failed: %w", err)
		}
		fmt.Println(msg)
		return nil
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
