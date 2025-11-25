package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/containerd/containerd/api/events"
	taskAPI "github.com/containerd/containerd/api/runtime/task/v2"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/runtime/v2/shim"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *service) StartShim(ctx context.Context, opts shim.StartOpts) (string, error) {
	return "", nil
}

func (s *service) Cleanup(ctx context.Context) (*taskAPI.DeleteResponse, error) {
	return &taskAPI.DeleteResponse{ExitedAt: timestamppb.New(time.Now()), ExitStatus: 0}, nil
}

func (s *service) Create(ctx context.Context, r *taskAPI.CreateTaskRequest) (*taskAPI.CreateTaskResponse, error) {
	args := []string{"create", "--bundle", r.Bundle, "--pid-file", filepath.Join(r.Bundle, "pid"), r.ID}
	cmd := exec.CommandContext(ctx, "/usr/local/bin/runtime", args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("create failed: %w", err)
	}
	pidData, _ := os.ReadFile(filepath.Join(r.Bundle, "pid"))
	var pid uint32
	fmt.Sscanf(string(pidData), "%d", &pid)
	return &taskAPI.CreateTaskResponse{Pid: pid}, nil
}

func (s *service) Start(ctx context.Context, r *taskAPI.StartRequest) (*taskAPI.StartResponse, error) {
	cmd := exec.CommandContext(ctx, "/usr/local/bin/runtime", "start", r.ID)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	s.publisher.Publish(ctx, "/tasks/start", &events.TaskStart{ContainerID: r.ID})
	return &taskAPI.StartResponse{Pid: 0}, nil
}

func (s *service) Delete(ctx context.Context, r *taskAPI.DeleteRequest) (*taskAPI.DeleteResponse, error) {
	cmd := exec.CommandContext(ctx, "/usr/local/bin/runtime", "delete", r.ID)
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return &taskAPI.DeleteResponse{ExitedAt: timestamppb.New(time.Now()), ExitStatus: 0}, nil
}

func (s *service) Pids(ctx context.Context, r *taskAPI.PidsRequest) (*taskAPI.PidsResponse, error) {
	return &taskAPI.PidsResponse{}, nil
}

func (s *service) Pause(ctx context.Context, r *taskAPI.PauseRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, exec.CommandContext(ctx, "/usr/local/bin/runtime", "pause", r.ID).Run()
}

func (s *service) Resume(ctx context.Context, r *taskAPI.ResumeRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, exec.CommandContext(ctx, "/usr/local/bin/runtime", "resume", r.ID).Run()
}

func (s *service) Checkpoint(ctx context.Context, r *taskAPI.CheckpointTaskRequest) (*emptypb.Empty, error) {
	return nil, errdefs.ErrNotImplemented
}

func (s *service) Kill(ctx context.Context, r *taskAPI.KillRequest) (*emptypb.Empty, error) {
	args := []string{"kill", r.ID, fmt.Sprintf("%d", r.Signal)}
	return &emptypb.Empty{}, exec.CommandContext(ctx, "/usr/local/bin/runtime", args...).Run()
}

func (s *service) Exec(ctx context.Context, r *taskAPI.ExecProcessRequest) (*emptypb.Empty, error) {
	return nil, errdefs.ErrNotImplemented
}

func (s *service) ResizePty(ctx context.Context, r *taskAPI.ResizePtyRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (s *service) State(ctx context.Context, r *taskAPI.StateRequest) (*taskAPI.StateResponse, error) {
	return &taskAPI.StateResponse{ID: r.ID, Status: 0}, nil
}

func (s *service) Shutdown(ctx context.Context, r *taskAPI.ShutdownRequest) (*emptypb.Empty, error) {
	s.shutdown()
	return &emptypb.Empty{}, nil
}

func (s *service) Stats(ctx context.Context, r *taskAPI.StatsRequest) (*taskAPI.StatsResponse, error) {
	any, _ := anypb.New(&emptypb.Empty{})
	return &taskAPI.StatsResponse{Stats: any}, nil
}

func (s *service) Connect(ctx context.Context, r *taskAPI.ConnectRequest) (*taskAPI.ConnectResponse, error) {
	return &taskAPI.ConnectResponse{ShimPid: uint32(os.Getpid()), TaskPid: 0}, nil
}

func (s *service) Wait(ctx context.Context, r *taskAPI.WaitRequest) (*taskAPI.WaitResponse, error) {
	return &taskAPI.WaitResponse{ExitStatus: 0, ExitedAt: timestamppb.New(time.Now())}, nil
}

func (s *service) Update(ctx context.Context, r *taskAPI.UpdateTaskRequest) (*emptypb.Empty, error) {
	return nil, errdefs.ErrNotImplemented
}

func (s *service) CloseIO(ctx context.Context, r *taskAPI.CloseIORequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
