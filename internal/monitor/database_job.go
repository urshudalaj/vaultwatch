package monitor

import (
	"fmt"
	"time"
)

// DatabaseRoleReader is the interface satisfied by vault.DatabaseChecker.
type DatabaseRoleReader interface {
	GetRole(mount, role string) (interface{ GetDefaultTTL() int; GetMaxTTL() int }, error)
}

// dbRoleInfo is a minimal interface for role TTL data.
type dbRoleInfo interface {
	GetDefaultTTL() int
	GetMaxTTL() int
}

// DatabaseRoleGetter is a narrow interface used by DatabaseJob.
type DatabaseRoleGetter interface {
	GetRole(mount, role string) (defaultTTL, maxTTL int, err error)
}

// DatabaseJob checks that database roles have non-zero TTLs configured.
type DatabaseJob struct {
	getter  DatabaseRoleGetter
	mount   string
	role    string
	notify  func(Alert)
}

// NewDatabaseJob constructs a DatabaseJob.
func NewDatabaseJob(getter DatabaseRoleGetter, mount, role string, notify func(Alert)) *DatabaseJob {
	return &DatabaseJob{getter: getter, mount: mount, role: role, notify: notify}
}

// Run executes the database role TTL check.
func (j *DatabaseJob) Run() {
	defaultTTL, maxTTL, err := j.getter.GetRole(j.mount, j.role)
	if err != nil {
		j.notify(Alert{
			Level:   Critical,
			Message: fmt.Sprintf("database job: failed to read role %s/%s: %v", j.mount, j.role, err),
			At:      time.Now(),
		})
		return
	}
	if defaultTTL == 0 {
		j.notify(Alert{
			Level:   Warning,
			Message: fmt.Sprintf("database role %s/%s has no default_ttl configured", j.mount, j.role),
			At:      time.Now(),
		})
	}
	if maxTTL == 0 {
		j.notify(Alert{
			Level:   Warning,
			Message: fmt.Sprintf("database role %s/%s has no max_ttl configured", j.mount, j.role),
			At:      time.Now(),
		})
	}
}
