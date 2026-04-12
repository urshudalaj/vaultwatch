package monitor

import (
	"fmt"
	"log"
)

// EntityLister lists entity IDs from Vault.
type EntityLister interface {
	ListEntities() ([]string, error)
}

// EntityGetter retrieves a single entity by ID.
type EntityGetter interface {
	GetEntity(id string) (*EntityInfo, error)
}

// EntityInfo mirrors vault.EntityInfo for the monitor layer.
type EntityInfo struct {
	ID       string
	Name     string
	Disabled bool
	Policies []string
}

// EntityChecker combines listing and fetching.
type EntityChecker interface {
	ListEntities() ([]string, error)
	GetEntity(id string) (*entityInfoInternal, error)
}

type entityInfoInternal = struct {
	ID       string
	Name     string
	Disabled bool
	Policies []string
}

// entityCheckerAdapter wraps the vault.EntityChecker to satisfy EntityChecker.
type entityCheckerAdapter interface {
	ListEntities() ([]string, error)
	GetEntity(id string) (interface{ GetDisabled() bool; GetName() string }, error)
}

// EntityJobChecker is the minimal interface consumed by NewEntityJob.
type EntityJobChecker interface {
	ListEntities() ([]string, error)
	GetEntity(id string) (*vaultEntityInfo, error)
}

type vaultEntityInfo struct {
	ID       string
	Name     string
	Disabled bool
	Policies []string
}

// EntityJob checks for disabled identity entities and emits alerts.
type EntityJob struct {
	checker EntityJobChecker
	alerts  chan<- Alert
}

// NewEntityJob creates an EntityJob that sends alerts to the provided channel.
func NewEntityJob(checker EntityJobChecker, alerts chan<- Alert) *EntityJob {
	return &EntityJob{checker: checker, alerts: alerts}
}

// Run lists all entities and alerts on any that are disabled.
func (j *EntityJob) Run() {
	ids, err := j.checker.ListEntities()
	if err != nil {
		log.Printf("entity_job: list error: %v", err)
		return
	}
	for _, id := range ids {
		info, err := j.checker.GetEntity(id)
		if err != nil {
			log.Printf("entity_job: get entity %s error: %v", id, err)
			continue
		}
		if info.Disabled {
			j.alerts <- Alert{
				Level:   LevelWarning,
				Message: fmt.Sprintf("identity entity %q (id=%s) is disabled", info.Name, info.ID),
			}
		}
	}
}
