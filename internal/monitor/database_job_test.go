package monitor

import (
	"errors"
	"testing"
)

type stubDatabaseGetter struct {
	defaultTTL int
	maxTTL     int
	err        error
}

func (s *stubDatabaseGetter) GetRole(_, _ string) (int, int, error) {
	return s.defaultTTL, s.maxTTL, s.err
}

func dbJobWithStub(stub *stubDatabaseGetter) (*DatabaseJob, *[]Alert) {
	var alerts []Alert
	job := NewDatabaseJob(stub, "database", "readonly", func(a Alert) {
		alerts = append(alerts, a)
	})
	return job, &alerts
}

func TestDatabaseJob_NoAlertWhenTTLsConfigured(t *testing.T) {
	job, alerts := dbJobWithStub(&stubDatabaseGetter{defaultTTL: 3600, maxTTL: 86400})
	job.Run()
	if len(*alerts) != 0 {
		t.Errorf("expected no alerts, got %d", len(*alerts))
	}
}

func TestDatabaseJob_AlertWhenDefaultTTLMissing(t *testing.T) {
	job, alerts := dbJobWithStub(&stubDatabaseGetter{defaultTTL: 0, maxTTL: 86400})
	job.Run()
	if len(*alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(*alerts))
	}
	if (*alerts)[0].Level != Warning {
		t.Errorf("expected Warning level")
	}
}

func TestDatabaseJob_AlertWhenMaxTTLMissing(t *testing.T) {
	job, alerts := dbJobWithStub(&stubDatabaseGetter{defaultTTL: 3600, maxTTL: 0})
	job.Run()
	if len(*alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(*alerts))
	}
	if (*alerts)[0].Level != Warning {
		t.Errorf("expected Warning level")
	}
}

func TestDatabaseJob_AlertOnCheckerError(t *testing.T) {
	job, alerts := dbJobWithStub(&stubDatabaseGetter{err: errors.New("vault unreachable")})
	job.Run()
	if len(*alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(*alerts))
	}
	if (*alerts)[0].Level != Critical {
		t.Errorf("expected Critical level")
	}
}
