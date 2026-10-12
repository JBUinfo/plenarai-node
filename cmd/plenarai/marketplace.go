package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/plenarai/cli/internal/auth"
	"github.com/plenarai/cli/internal/config"
	"github.com/spf13/cobra"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type providerRow struct {
	UserID         string  `json:"user_id"`
	ModelName      string  `json:"model_name"`
	Availability   string  `json:"availability"`
	UniqueUsers    int     `json:"unique_users_7d"`
	ReturningUsers int     `json:"returning_users_7d"`
	Completed      int     `json:"completed_directed_7d"`
	MinCost        float64 `json:"min_question_cost"`
}

func init() {
	var search string
	providers := &cobra.Command{Use: "providers", Short: "Discover independent AI providers by seven-day directed usage", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		client := &http.Client{Timeout: 20 * time.Second}
		resp, err := client.Get(config.ServerURL + "/v0/providers?limit=100&q=" + url.QueryEscape(search))
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("catalog returned %d", resp.StatusCode)
		}
		var rows []providerRow
		if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
			return err
		}
		fmt.Println("Popularity is usage, not verified quality. Beta credits have no cash payout.")
		for _, p := range rows {
			fmt.Printf("%s  %s  %s  accounts=%d returning=%d completed=%d min=%.2f\n", p.UserID, p.ModelName, p.Availability, p.UniqueUsers, p.ReturningUsers, p.Completed, math.Max(1, p.MinCost))
		}
		if len(rows) == 0 {
			fmt.Println("No published providers.")
		}
		fmt.Println("Choose a provider: plenarai chat --node-id <UUID>")
		return nil
	}}
	providers.Flags().StringVar(&search, "search", "", "filter model, description, topics or language")
	rootCmd.AddCommand(providers)

	var description, tags, languages string
	profile := &cobra.Command{Use: "provider-profile", Short: "Replace your public description, topics and language tags", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		auth.LoadConfig()
		header, err := auth.AuthHeader()
		if err != nil {
			return err
		}
		list := func(value string) []string {
			out := []string{}
			for _, v := range strings.Split(value, ",") {
				if v = strings.TrimSpace(v); v != "" {
					out = append(out, v)
				}
			}
			return out
		}
		body, err := json.Marshal(map[string]interface{}{"description": description, "tags": list(tags), "languages": list(languages)})
		if err != nil {
			return err
		}
		req, err := http.NewRequest(http.MethodPut, config.ServerURL+"/v0/node/profile", bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", header)
		req.Header.Set("Content-Type", "application/json")
		resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			var result struct {
				Error string `json:"error"`
			}
			json.NewDecoder(resp.Body).Decode(&result)
			return fmt.Errorf("profile update failed (%d): %s", resp.StatusCode, result.Error)
		}
		fmt.Println("Public profile updated.")
		return nil
	}}
	profile.Flags().StringVar(&description, "description", "", "public description, up to 1000 characters")
	profile.Flags().StringVar(&tags, "tags", "", "comma separated topics, up to 5")
	profile.Flags().StringVar(&languages, "languages", "", "comma separated language tags, up to 8, e.g. en,es")
	rootCmd.AddCommand(profile)
}
