package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/containerd/containerd/api/events"
	taskAPI "github.com/containerd/containerd/api/runtime/task/v2"
	"github.com/containerd/containerd/api/types/task"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/runtime/v2/shim"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const runtimePath = "/usr/local/bin/runtime"

// ContainerState represents the JSON output from runtime state command
type ContainerState struct {
	OCIVersion  string            `json:"ociVersion"`
	ID          string            `json:"id"`
	Pid         int               `json:"pid"`
	Status      string            `json:"status"`
	Bundle      string            `json:"bundle"`
	Annotations map[string]string `json:"annotations"`
}

// RuntimeStats represents stats from runtime events --stats
type RuntimeStats struct {
	Timestamp string `json:"timestamp"`
	CPU       struct {
		Usage struct {
			Total uint64 `json:"total"`
		} `json:"usage"`
	} `json:"cpu"`
	Memory struct {
		Usage struct {
			RSS uint64 `json:"rss"`
		} `json:"usage"`
	} `json:"memory"`
	Pids struct {
		Current uint64 `json:"current"`
	} `json:"pids"`
}

// ExecProcess tracks an exec process
type ExecProcess struct {
	ID       string
	Pid      uint32
	Status   int
	ExitedAt time.Time
	Exited   bool
}

func (s *service) StartShim(ctx context.Context, opts shim.StartOpts) (string, error) {
	return "", nil
}

func (s *service) Cleanup(ctx context.Context) (*taskAPI.DeleteResponse, error) {
	return &taskAPI.DeleteResponse{ExitedAt: timestamppb.New(time.Now()), ExitStatus: 0}, nil
}

func (s *service) Create(ctx context.Context, r *taskAPI.CreateTaskRequest) (*taskAPI.CreateTaskResponse, error) {
	s.mu.Lock()
	s.bundle = r.Bundle
	s.containerID = r.ID
	s.mu.Unlock()

	args := []string{"create", "--bundle", r.Bundle, "--pid-file", filepath.Join(r.Bundle, "pid")}

	// Add console socket if terminal is requested
	if r.Terminal {
		if r.Stdin != "" {
			args = append(args, "--console-socket", r.Stdin)
		}
	}

	args = append(args, r.ID)

	cmd := exec.CommandContext(ctx, runtimePath, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("create failed: %w", err)
	}

	pidData, err := os.ReadFile(filepath.Join(r.Bundle, "pid"))
	if err != nil {
		return nil, fmt.Errorf("failed to read pid file: %w", err)
	}

	pid, err := strconv.ParseUint(strings.TrimSpace(string(pidData)), 10, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pid: %w", err)
	}

	s.mu.Lock()
	s.initPid = uint32(pid)
	s.mu.Unlock()

	return &taskAPI.CreateTaskResponse{Pid: uint32(pid)}, nil
}

func (s *service) Start(ctx context.Context, r *taskAPI.StartRequest) (*taskAPI.StartResponse, error) {
	// If ExecID is set, this is starting an exec process
	if r.ExecID != "" {
		s.mu.Lock()
		ep, ok := s.execProcesses[r.ExecID]
		s.mu.Unlock()

		if !ok {
			return nil, errdefs.ErrNotFound
		}

		return &taskAPI.StartResponse{Pid: ep.Pid}, nil
	}

	cmd := exec.CommandContext(ctx, runtimePath, "start", r.ID)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, err
	}

	s.publisher.Publish(ctx, "/tasks/start", &events.TaskStart{ContainerID: r.ID})

	s.mu.Lock()
	pid := s.initPid
	s.mu.Unlock()

	return &taskAPI.StartResponse{Pid: pid}, nil
}

func (s *service) Delete(ctx context.Context, r *taskAPI.DeleteRequest) (*taskAPI.DeleteResponse, error) {
	// If ExecID is set, delete the exec process
	if r.ExecID != "" {
		s.mu.Lock()
		ep, ok := s.execProcesses[r.ExecID]
		if ok {
			delete(s.execProcesses, r.ExecID)
		}
		s.mu.Unlock()

		if !ok {
			return nil, errdefs.ErrNotFound
		}

		return &taskAPI.DeleteResponse{
			Pid:        ep.Pid,
			ExitStatus: uint32(ep.Status),
			ExitedAt:   timestamppb.New(ep.ExitedAt),
		}, nil
	}

	// Delete the main container
	cmd := exec.CommandContext(ctx, runtimePath, "delete", "--force", r.ID)
	cmd.Run() // Ignore error - container may already be deleted

	s.mu.Lock()
	exitStatus := s.exitStatus
	exitedAt := s.exitedAt
	pid := s.initPid
	s.mu.Unlock()

	return &taskAPI.DeleteResponse{
		Pid:        pid,
		ExitStatus: exitStatus,
		ExitedAt:   timestamppb.New(exitedAt),
	}, nil
}

func (s *service) Pids(ctx context.Context, r *taskAPI.PidsRequest) (*taskAPI.PidsResponse, error) {
	cmd := exec.CommandContext(ctx, runtimePath, "ps", r.ID)
	output, err := cmd.Output()
	if err != nil {
		return &taskAPI.PidsResponse{}, nil
	}

	var processes []*task.ProcessInfo
	scanner := bufio.NewScanner(bytes.NewReader(output))

	// Skip header line
	if scanner.Scan() {
		// Header: "PID\tCMD"
	}

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) >= 1 {
			pid, err := strconv.ParseUint(parts[0], 10, 32)
			if err != nil {
				continue
			}
			processes = append(processes, &task.ProcessInfo{
				Pid: uint32(pid),
			})
		}
	}

	return &taskAPI.PidsResponse{Processes: processes}, nil
}

func (s *service) Pause(ctx context.Context, r *taskAPI.PauseRequest) (*emptypb.Empty, error) {
	cmd := exec.CommandContext(ctx, runtimePath, "pause", r.ID)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("pause failed: %w", err)
	}
	return &emptypb.Empty{}, nil
}

func (s *service) Resume(ctx context.Context, r *taskAPI.ResumeRequest) (*emptypb.Empty, error) {
	cmd := exec.CommandContext(ctx, runtimePath, "resume", r.ID)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("resume failed: %w", err)
	}
	return &emptypb.Empty{}, nil
}

func (s *service) Checkpoint(ctx context.Context, r *taskAPI.CheckpointTaskRequest) (*emptypb.Empty, error) {
	return nil, errdefs.ErrNotImplemented
}

func (s *service) Kill(ctx context.Context, r *taskAPI.KillRequest) (*emptypb.Empty, error) {
	// If ExecID is set, kill the exec process
	if r.ExecID != "" {
		s.mu.Lock()
		ep, ok := s.execProcesses[r.ExecID]
		s.mu.Unlock()

		if !ok {
			return nil, errdefs.ErrNotFound
		}

		if ep.Pid > 0 {
			// Send signal to the exec process
			proc, err := os.FindProcess(int(ep.Pid))
			if err == nil {
				proc.Signal(syscall.Signal(r.Signal))
			}
		}
		return &emptypb.Empty{}, nil
	}

	args := []string{"kill", r.ID, fmt.Sprintf("%d", r.Signal)}
	cmd := exec.CommandContext(ctx, runtimePath, args...)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("kill failed: %w", err)
	}

	// Update exit status for SIGKILL/SIGTERM
	if r.Signal == 9 || r.Signal == 15 {
		s.mu.Lock()
		s.exitStatus = 128 + r.Signal
		s.exitedAt = time.Now()
		s.mu.Unlock()
	}

	return &emptypb.Empty{}, nil
}

func (s *service) Exec(ctx context.Context, r *taskAPI.ExecProcessRequest) (*emptypb.Empty, error) {
	// Write the process spec to a temporary file
	specFile := filepath.Join(s.bundle, fmt.Sprintf("exec-%s.json", r.ExecID))

	if r.Spec != nil {
		specData := r.Spec.GetValue()
		if len(specData) > 0 {
			if err := os.WriteFile(specFile, specData, 0644); err != nil {
				return nil, fmt.Errorf("failed to write exec spec: %w", err)
			}
		}
	}

	// Build exec command arguments
	args := []string{"exec", "--detach"}

	pidFile := filepath.Join(s.bundle, fmt.Sprintf("exec-%s.pid", r.ExecID))
	args = append(args, "--pid-file", pidFile)

	if r.Spec != nil {
		args = append(args, "--process", specFile)
	}

	args = append(args, r.ID)

	cmd := exec.CommandContext(ctx, runtimePath, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr

	if err := cmd.Run(); err != nil {
		os.Remove(specFile)
		return nil, fmt.Errorf("exec failed: %w", err)
	}

	// Read the pid file
	var pid uint32
	if pidData, err := os.ReadFile(pidFile); err == nil {
		if p, err := strconv.ParseUint(strings.TrimSpace(string(pidData)), 10, 32); err == nil {
			pid = uint32(p)
		}
	}

	// Track the exec process
	s.mu.Lock()
	if s.execProcesses == nil {
		s.execProcesses = make(map[string]*ExecProcess)
	}
	s.execProcesses[r.ExecID] = &ExecProcess{
		ID:  r.ExecID,
		Pid: pid,
	}
	s.mu.Unlock()

	// Clean up spec file
	os.Remove(specFile)

	return &emptypb.Empty{}, nil
}

func (s *service) ResizePty(ctx context.Context, r *taskAPI.ResizePtyRequest) (*emptypb.Empty, error) {
	// PTY resize is not fully implemented in the runtime
	return &emptypb.Empty{}, nil
}

func (s *service) State(ctx context.Context, r *taskAPI.StateRequest) (*taskAPI.StateResponse, error) {
	// If ExecID is set, return exec process state
	if r.ExecID != "" {
		s.mu.Lock()
		ep, ok := s.execProcesses[r.ExecID]
		s.mu.Unlock()

		if !ok {
			return nil, errdefs.ErrNotFound
		}

		status := task.Status_RUNNING
		if ep.Exited {
			status = task.Status_STOPPED
		}

		return &taskAPI.StateResponse{
			ID:         r.ExecID,
			Pid:        ep.Pid,
			Status:     status,
			ExitStatus: uint32(ep.Status),
			ExitedAt:   timestamppb.New(ep.ExitedAt),
		}, nil
	}

	cmd := exec.CommandContext(ctx, runtimePath, "state", r.ID)
	output, err := cmd.Output()
	if err != nil {
		// Return basic state if command fails
		s.mu.Lock()
		pid := s.initPid
		s.mu.Unlock()
		return &taskAPI.StateResponse{
			ID:     r.ID,
			Pid:    pid,
			Status: task.Status_UNKNOWN,
		}, nil
	}

	var state ContainerState
	if err := json.Unmarshal(output, &state); err != nil {
		return nil, fmt.Errorf("failed to parse state: %w", err)
	}

	// Map runtime status to containerd status
	var status task.Status
	switch state.Status {
	case "creating":
		status = task.Status_CREATED
	case "created":
		status = task.Status_CREATED
	case "running":
		status = task.Status_RUNNING
	case "paused":
		status = task.Status_PAUSED
	case "stopped":
		status = task.Status_STOPPED
	default:
		status = task.Status_UNKNOWN
	}

	s.mu.Lock()
	exitStatus := s.exitStatus
	exitedAt := s.exitedAt
	s.mu.Unlock()

	return &taskAPI.StateResponse{
		ID:         state.ID,
		Bundle:     state.Bundle,
		Pid:        uint32(state.Pid),
		Status:     status,
		ExitStatus: exitStatus,
		ExitedAt:   timestamppb.New(exitedAt),
	}, nil
}

func (s *service) Shutdown(ctx context.Context, r *taskAPI.ShutdownRequest) (*emptypb.Empty, error) {
	s.shutdown()
	return &emptypb.Empty{}, nil
}

func (s *service) Stats(ctx context.Context, r *taskAPI.StatsRequest) (*taskAPI.StatsResponse, error) {
	cmd := exec.CommandContext(ctx, runtimePath, "events", "--stats", r.ID)
	output, err := cmd.Output()
	if err != nil {
		// Return empty stats if command fails
		any, _ := anypb.New(&emptypb.Empty{})
		return &taskAPI.StatsResponse{Stats: any}, nil
	}

	// Parse the stats event wrapper
	var statsEvent struct {
		Data RuntimeStats `json:"data"`
	}

	if err := json.Unmarshal(output, &statsEvent); err != nil {
		any, _ := anypb.New(&emptypb.Empty{})
		return &taskAPI.StatsResponse{Stats: any}, nil
	}

	// Return stats as Any - simplified version
	any, _ := anypb.New(&emptypb.Empty{})
	return &taskAPI.StatsResponse{Stats: any}, nil
}

func (s *service) Connect(ctx context.Context, r *taskAPI.ConnectRequest) (*taskAPI.ConnectResponse, error) {
	s.mu.Lock()
	pid := s.initPid
	s.mu.Unlock()

	return &taskAPI.ConnectResponse{
		ShimPid: uint32(os.Getpid()),
		TaskPid: pid,
	}, nil
}

func (s *service) Wait(ctx context.Context, r *taskAPI.WaitRequest) (*taskAPI.WaitResponse, error) {
	// If ExecID is set, wait for exec process
	if r.ExecID != "" {
		s.mu.Lock()
		ep, ok := s.execProcesses[r.ExecID]
		s.mu.Unlock()

		if !ok {
			return nil, errdefs.ErrNotFound
		}

		// Wait for the process to exit
		if ep.Pid > 0 && !ep.Exited {
			proc, err := os.FindProcess(int(ep.Pid))
			if err == nil {
				state, _ := proc.Wait()
				s.mu.Lock()
				ep.Exited = true
				ep.ExitedAt = time.Now()
				if state != nil {
					ep.Status = state.ExitCode()
				}
				s.mu.Unlock()
			}
		}

		return &taskAPI.WaitResponse{
			ExitStatus: uint32(ep.Status),
			ExitedAt:   timestamppb.New(ep.ExitedAt),
		}, nil
	}

	// Wait for the main container process
	s.mu.Lock()
	pid := s.initPid
	s.mu.Unlock()

	if pid > 0 {
		proc, err := os.FindProcess(int(pid))
		if err == nil {
			state, _ := proc.Wait()
			s.mu.Lock()
			s.exitedAt = time.Now()
			if state != nil {
				s.exitStatus = uint32(state.ExitCode())
			}
			s.mu.Unlock()
		}
	}

	s.mu.Lock()
	exitStatus := s.exitStatus
	exitedAt := s.exitedAt
	s.mu.Unlock()

	return &taskAPI.WaitResponse{
		ExitStatus: exitStatus,
		ExitedAt:   timestamppb.New(exitedAt),
	}, nil
}

func (s *service) Update(ctx context.Context, r *taskAPI.UpdateTaskRequest) (*emptypb.Empty, error) {
	// Update is not implemented in the runtime
	return nil, errdefs.ErrNotImplemented
}

func (s *service) CloseIO(ctx context.Context, r *taskAPI.CloseIORequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
