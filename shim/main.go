package main

import (
	"context"
	"sync"
	"time"

	"github.com/containerd/containerd/runtime/v2/shim"
)

func main() {
	shim.Run("io.containerd.runway.v2", NewService)
}

func NewService(ctx context.Context, id string, remotePublisher shim.Publisher, shutdown func()) (shim.Shim, error) {
	return &service{
		id:            id,
		context:       ctx,
		publisher:     remotePublisher,
		shutdown:      shutdown,
		execProcesses: make(map[string]*ExecProcess),
	}, nil
}

type service struct {
	id            string
	context       context.Context
	publisher     shim.Publisher
	shutdown      func()
	mu            sync.Mutex
	bundle        string
	containerID   string
	initPid       uint32
	exitStatus    uint32
	exitedAt      time.Time
	execProcesses map[string]*ExecProcess
}
