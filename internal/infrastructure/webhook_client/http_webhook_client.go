package webhookclient

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
)

type Client struct {
	webhookURL string
	client     *http.Client
	log *slog.Logger
}

//it'll throw a panic if something goes wrong
func MustInitNewClient(webhookURL string, log *slog.Logger) *Client {
	client := &http.Client{
		Timeout: time.Duration(time.Second * 10),
	}

	if webhookURL == "" {
		panic("empty webhookURL")
	}
	return &Client{client: client, webhookURL: webhookURL, log: log}
}

func (hc *Client) NotifyIPChange(ctx context.Context, userID uuid.UUID, oldIP, newIP string) {
	payload := map[string]interface{}{
		"user_id": userID.String(),
		"old_ip":  oldIP,
		"new_ip":  newIP,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		hc.log.Error("HTTP Client error", "error", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", hc.webhookURL, bytes.NewBuffer(body))
	if err != nil {
		hc.log.Error("HTTP Client error", "error", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := hc.client.Do(req)
	if err != nil {
		hc.log.Error("HTTP Client error", "error", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		hc.log.Error("HTTP Client error", "error", "unexpected status code returned from webhook", "code", resp.StatusCode)
	}
}
