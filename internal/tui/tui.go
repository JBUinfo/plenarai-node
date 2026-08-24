package tui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/plenarai/cli/internal/auth"
	"github.com/plenarai/cli/internal/config"
	"github.com/plenarai/cli/internal/questioner"
)

var (
	titleStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("205"))
	statusStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	errorStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
)

type state int

const (
	stateMenu state = iota
	stateAsk
	stateWaiting
	stateResult
)

type Model struct {
	state     state
	input     string
	result    string
	err       string
	cursor    int
	menuItems []string
}

func NewModel() Model {
	return Model{
		state:     stateMenu,
		menuItems: []string{"Ask a question", "Check balance", "Quit"},
	}
}

func (m Model) Init() tea.Cmd {
	return nil
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch m.state {
		case stateMenu:
			switch msg.String() {
			case "up", "k":
				if m.cursor > 0 {
					m.cursor--
				}
			case "down", "j":
				if m.cursor < len(m.menuItems)-1 {
					m.cursor++
				}
			case "enter":
				switch m.cursor {
				case 0:
					m.state = stateAsk
					m.input = ""
				case 1:
					m.result = fetchBalance()
					m.state = stateResult
				case 2:
					return m, tea.Quit
				}
			case "q", "ctrl+c":
				return m, tea.Quit
			}
		case stateAsk:
			switch msg.String() {
			case "enter":
				if m.input != "" {
					m.result = submitAndWait(m.input)
					m.state = stateResult
				}
			case "esc":
				m.state = stateMenu
			case "ctrl+c":
				return m, tea.Quit
			case "backspace":
				if len(m.input) > 0 {
					m.input = m.input[:len(m.input)-1]
				}
			default:
				if len(msg.String()) == 1 || msg.String() == " " {
					m.input += msg.String()
				}
			}
		case stateResult:
			switch msg.String() {
			case "esc", "enter":
				m.state = stateMenu
				m.result = ""
				m.err = ""
			case "q", "ctrl+c":
				return m, tea.Quit
			}
		}
	}
	return m, nil
}

func (m Model) View() string {
	s := titleStyle.Render("  PlenarAI") + "\n\n"

	switch m.state {
	case stateMenu:
		for i, item := range m.menuItems {
			cursor := "  "
			if m.cursor == i {
				cursor = "> "
			}
			s += cursor + item + "\n"
		}
		s += "\n" + statusStyle.Render("Use arrows to navigate, enter to select, q to quit")
	case stateAsk:
		s += "Enter your question:\n\n"
		s += "> " + m.input + "█\n\n"
		s += statusStyle.Render("Press enter to submit, esc to go back")
	case stateResult:
		if m.err != "" {
			s += errorStyle.Render(m.err) + "\n"
		} else {
			s += m.result + "\n"
		}
		s += "\n" + statusStyle.Render("Press enter or esc to go back")
	}

	return s
}

func Run() error {
	p := tea.NewProgram(NewModel())
	_, err := p.Run()
	return err
}

func submitAndWait(question string) string {
	result, err := questioner.Ask(question, "")
	if err != nil {
		return fmt.Sprintf("Error: %v", err)
	}
	for i := 0; i < 30; i++ {
		time.Sleep(2 * time.Second)
		poll, err := questioner.PollResult(result.QuestionID)
		if err != nil {
			continue
		}
		if poll.Status == "completed" {
			return fmt.Sprintf("Answer (score %.2f):\n\n%s", poll.Score, poll.Answer)
		}
		if poll.Status == "failed" {
			return "Question failed - no responses received."
		}
	}
	return fmt.Sprintf("Timeout. Question ID: %s", result.QuestionID)
}

func fetchBalance() string {
	header, err := auth.AuthHeader()
	if err != nil {
		return "Not logged in. Use 'plenarai login' first."
	}

	req, _ := http.NewRequest(http.MethodGet, config.ServerURL+"/v0/wallet", nil)
	req.Header.Set("Authorization", header)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Sprintf("Connection error: %v", err)
	}
	defer resp.Body.Close()

	var wallet struct {
		BalanceCredits float64 `json:"balance_credits"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wallet); err != nil {
		return "Failed to read balance"
	}

	return fmt.Sprintf("Balance: %.4f credits", wallet.BalanceCredits)
}
