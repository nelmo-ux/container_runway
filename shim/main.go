package main

import (
	"context"

	"github.com/containerd/containerd/runtime/v2/shim"
)

func main() {
	shim.Run("io.containerd.runway.v2", NewService)
}

func NewService(ctx context.Context, id string, remotePublisher shim.Publisher, shutdown func()) (shim.Shim, error) {
	return &service{
		id:        id,
		context:   ctx,
		publisher: remotePublisher,
		shutdown:  shutdown,
	}, nil
}

type service struct {
	id        string
	context   context.Context
	publisher shim.Publisher
	shutdown  func()
}
