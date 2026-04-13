package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// TelemetryInfo holds key metrics from the Vault telemetry endpoint.
type TelemetryInfo struct {
	Counters map[string]float64 `json:"counters"`
	Gauges   map[string]float64 `json:"gauges"`
}

// TelemetryChecker retrieves telemetry data from Vault.
type TelemetryChecker struct {
	client *http.Client
	baseURL string
	token   string
}

// NewTelemetryChecker creates a new TelemetryChecker.
func NewTelemetryChecker(baseURL, token string, client *http.Client) *TelemetryChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &TelemetryChecker{
		client:  client,
		baseURL: baseURL,
		token:   token,
	}
}

// GetTelemetry fetches telemetry metrics from the Vault sys/metrics endpoint.
func (t *TelemetryChecker) GetTelemetry() (*TelemetryInfo, error) {
	url := fmt.Sprintf("%s/v1/sys/metrics?format=json", t.baseURL)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("telemetry: create request: %w", err)
	}
	req.Header.Set("X-Vault-Token", t.token)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("telemetry: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("telemetry: unexpected status %d", resp.StatusCode)
	}

	var raw struct {
		Counters []struct {
			Name  string  `json:"Name"`
			Count float64 `json:"Count"`
		} `json:"Counters"`
		Gauges []struct {
			Name  string  `json:"Name"`
			Value float64 `json:"Value"`
		} `json:"Gauges"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("telemetry: decode response: %w", err)
	}

	info := &TelemetryInfo{
		Counters: make(map[string]float64, len(raw.Counters)),
		Gauges:   make(map[string]float64, len(raw.Gauges)),
	}
	for _, c := range raw.Counters {
		info.Counters[c.Name] = c.Count
	}
	for _, g := range raw.Gauges {
		info.Gauges[g.Name] = g.Value
	}
	return info, nil
}
