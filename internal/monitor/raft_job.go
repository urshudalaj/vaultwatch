package monitor

import (
	"fmt"
	"log"

	"github.com/yourusername/vaultwatch/internal/vault"
)

// RaftJobConfig holds configuration for the raft monitor job.
type RaftJobConfig struct {
	// MaxFSMPending is the threshold above which an alert is raised.
	MaxFSMPending uint64
}

// raftChecker is the interface used by RaftJob.
type raftChecker interface {
	CheckRaft() (*vault.RaftStatus, error)
}

// RaftJob monitors Vault Raft storage health.
type RaftJob struct {
	checker raftChecker
	cfg     RaftJobConfig
	alerts  chan<- Alert
}

// NewRaftJob creates a new RaftJob.
func NewRaftJob(checker raftChecker, cfg RaftJobConfig, alerts chan<- Alert) *RaftJob {
	if cfg.MaxFSMPending == 0 {
		cfg.MaxFSMPending = 100
	}
	return &RaftJob{checker: checker, cfg: cfg, alerts: alerts}
}

// Run executes a single Raft health check cycle.
func (j *RaftJob) Run() {
	status, err := j.checker.CheckRaft()
	if err != nil {
		log.Printf("raft_job: check failed: %v", err)
		return
	}

	if status.LeaderID == "" {
		j.alerts <- Alert{
			Level:   Critical,
			Message: "raft: no leader elected",
		}
		return
	}

	if status.FSMPending > j.cfg.MaxFSMPending {
		j.alerts <- Alert{
			Level:   Warning,
			Message: fmt.Sprintf("raft: fsm_pending=%d exceeds threshold %d", status.FSMPending, j.cfg.MaxFSMPending),
		}
	}
}
