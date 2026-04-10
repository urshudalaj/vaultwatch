package notifier

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/user/vaultwatch/internal/monitor"
)

// Channel represents a notification delivery channel.
type Channel string

const (
	ChannelLog   Channel = "log"
	ChannelSlack Channel = "slack"
)

// Config holds configuration for the notifier.
type Config struct {
	Channel    Channel
	SlackURL   string
	HTTPClient *http.Client
}

// Notifier sends alerts through a configured channel.
type Notifier struct {
	cfg Config
}

// New creates a new Notifier with the given config.
func New(cfg Config) *Notifier {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &Notifier{cfg: cfg}
}

// Send dispatches an alert through the configured channel.
func (n *Notifier) Send(alert monitor.Alert) error {
	switch n.cfg.Channel {
	case ChannelSlack:
		return n.sendSlack(alert)
	case ChannelLog:
		fallthrough
	default:
		return n.sendLog(alert)
	}
}

func (n *Notifier) sendLog(alert monitor.Alert) error {
	log.Printf("[VAULTWATCH] %s", alert.String())
	return nil
}

func (n *Notifier) sendSlack(alert monitor.Alert) error {
	if n.cfg.SlackURL == "" {
		return fmt.Errorf("slack webhook URL is not configured")
	}
	payload := fmt.Sprintf(`{"text":"%s"}`, alert.String())
	resp, err := n.cfg.HTTPClient.Post(
		n.cfg.SlackURL,
		"application/json",
		strings.NewReader(payload),
	)
	if err != nil {
		return fmt.Errorf("slack notification failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack returned non-200 status: %d", resp.StatusCode)
	}
	return nil
}
