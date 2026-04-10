package notifier_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/user/vaultwatch/internal/monitor"
	"github.com/user/vaultwatch/internal/notifier"
)

func makeAlert(status monitor.LeaseStatus) monitor.Alert {
	return monitor.Alert{
		SecretPath: "secret/db/password",
		Status:     status,
		Remaining:  2 * time.Hour,
	}
}

func TestSend_LogChannel(t *testing.T) {
	n := notifier.New(notifier.Config{
		Channel: notifier.ChannelLog,
	})
	alert := makeAlert(monitor.StatusWarning)
	if err := n.Send(alert); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestSend_SlackChannel_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	n := notifier.New(notifier.Config{
		Channel:  notifier.ChannelSlack,
		SlackURL: server.URL,
	})
	alert := makeAlert(monitor.StatusCritical)
	if err := n.Send(alert); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestSend_SlackChannel_NoURL(t *testing.T) {
	n := notifier.New(notifier.Config{
		Channel: notifier.ChannelSlack,
	})
	alert := makeAlert(monitor.StatusWarning)
	if err := n.Send(alert); err == nil {
		t.Fatal("expected error when Slack URL is empty")
	}
}

func TestSend_SlackChannel_NonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	n := notifier.New(notifier.Config{
		Channel:  notifier.ChannelSlack,
		SlackURL: server.URL,
	})
	alert := makeAlert(monitor.StatusCritical)
	if err := n.Send(alert); err == nil {
		t.Fatal("expected error on non-200 Slack response")
	}
}

func TestNew_DefaultHTTPClient(t *testing.T) {
	n := notifier.New(notifier.Config{Channel: notifier.ChannelLog})
	if n == nil {
		t.Fatal("expected non-nil notifier")
	}
}
