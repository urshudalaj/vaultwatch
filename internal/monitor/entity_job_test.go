package monitor_test

import (
	"errors"
	"testing"

	"github.com/yourusername/vaultwatch/internal/monitor"
)

type stubEntityChecker struct {
	ids      []string
	entities map[string]*monitor.VaultEntityInfo
	listErr  error
	getErr   error
}

func (s *stubEntityChecker) ListEntities() ([]string, error) {
	return s.ids, s.listErr
}

func (s *stubEntityChecker) GetEntity(id string) (*monitor.VaultEntityInfo, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	return s.entities[id], nil
}

func entityJobWithStub(checker *stubEntityChecker) (*monitor.EntityJob, chan monitor.Alert) {
	ch := make(chan monitor.Alert, 10)
	return monitor.NewEntityJob(checker, ch), ch
}

func TestEntityJob_NoAlertWhenAllEnabled(t *testing.T) {
	stub := &stubEntityChecker{
		ids: []string{"id-1"},
		entities: map[string]*monitor.VaultEntityInfo{
			"id-1": {ID: "id-1", Name: "alice", Disabled: false},
		},
	}
	job, ch := entityJobWithStub(stub)
	job.Run()
	if len(ch) != 0 {
		t.Errorf("expected no alerts, got %d", len(ch))
	}
}

func TestEntityJob_AlertWhenDisabled(t *testing.T) {
	stub := &stubEntityChecker{
		ids: []string{"id-2"},
		entities: map[string]*monitor.VaultEntityInfo{
			"id-2": {ID: "id-2", Name: "bob", Disabled: true},
		},
	}
	job, ch := entityJobWithStub(stub)
	job.Run()
	if len(ch) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(ch))
	}
	a := <-ch
	if a.Level != monitor.LevelWarning {
		t.Errorf("expected warning level, got %s", a.Level)
	}
}

func TestEntityJob_SkipsAlertOnListError(t *testing.T) {
	stub := &stubEntityChecker{listErr: errors.New("permission denied")}
	job, ch := entityJobWithStub(stub)
	job.Run()
	if len(ch) != 0 {
		t.Errorf("expected no alerts on list error, got %d", len(ch))
	}
}

func TestEntityJob_SkipsEntityOnGetError(t *testing.T) {
	stub := &stubEntityChecker{
		ids:    []string{"id-3"},
		getErr: errors.New("not found"),
	}
	job, ch := entityJobWithStub(stub)
	job.Run()
	if len(ch) != 0 {
		t.Errorf("expected no alerts when get fails, got %d", len(ch))
	}
}
