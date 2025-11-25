# Container Runway Runtime - Architecture

## Overall Architecture

```mermaid
graph TB
    subgraph "Docker Integration"
        Docker[Docker Daemon]
        Containerd[Containerd]
        Shim[containerd-shim-runway-v2]
    end

    subgraph "Runway Runtime"
        Runtime[runtime binary]
        Create[create command]
        Start[start command]
        Kill[kill command]
        Delete[delete command]
    end

    subgraph "Container Process"
        Parent[Parent Process]
        Middle[Middle Process<br/>PID namespace]
        Container[Container Process<br/>PID 1]
    end

    Docker --> Containerd
    Containerd --> Shim
    Shim --> Runtime
    Runtime --> Create
    Create --> Parent
    Parent --> Middle
    Middle --> Container
    Runtime --> Start
    Runtime --> Kill
    Runtime --> Delete
```

## Process Lifecycle

```mermaid
sequenceDiagram
    participant Docker
    participant Runtime
    participant Parent
    participant Middle
    participant Container
    participant Process

    Docker->>Runtime: create <container-id>
    Runtime->>Runtime: load config.json
    Runtime->>Runtime: setup state
    Runtime->>Parent: fork()
    Parent->>Parent: release ContainerArgs
    Parent->>Middle: unshare(namespaces)
    Middle->>Container: fork() [if PID ns]
    Container->>Container: wait for FIFO signal
    Parent->>Runtime: return (created state)

    Docker->>Runtime: start <container-id>
    Runtime->>Container: write to FIFO
    Container->>Container: mount rootfs
    Container->>Container: pivot_root / chroot
    Container->>Container: mount /proc
    Container->>Container: apply masked paths
    Container->>Container: setup devices
    Container->>Process: execvp()

    Docker->>Runtime: kill <container-id>
    Runtime->>Parent: kill(SIGKILL)
    Parent-->>Middle: signal propagated
    Middle-->>Container: signal propagated
    Container-->>Process: terminated
    Runtime->>Runtime: update state (stopped)

    Docker->>Runtime: delete <container-id>
    Runtime->>Runtime: cleanup state files
    Runtime->>Runtime: cleanup cgroups
```

## Component Structure

```mermaid
graph LR
    subgraph "main.cpp"
        Main[main<br/>Entry Point]
        CreateC[create_container]
        StartC[start_container]
        KillC[kill_container]
        DeleteC[delete_container]
        ContainerMain[container_main]
    end

    subgraph "Runtime Modules"
        Config[config.cpp<br/>OCI Config]
        State[state.cpp<br/>State Management]
        Isolation[isolation.cpp<br/>Namespaces/Cgroups]
        Filesystem[filesystem.cpp<br/>Mount Operations]
        Process[process.cpp<br/>Process Tree]
        Console[console.cpp<br/>Terminal]
        Hooks[hooks.cpp<br/>Lifecycle Hooks]
        Options[options.cpp<br/>Global Options]
    end

    Main --> CreateC
    Main --> StartC
    Main --> KillC
    Main --> DeleteC

    CreateC --> Config
    CreateC --> State
    CreateC --> Isolation
    CreateC --> ContainerMain

    ContainerMain --> Filesystem
    ContainerMain --> Process

    StartC --> State
    StartC --> Hooks

    KillC --> State
    KillC --> Process

    DeleteC --> State
    DeleteC --> Isolation
```

## Memory Management Flow

```mermaid
graph TD
    A[create_container starts] --> B[unique_ptr&lt;ContainerArgs&gt; args]
    B --> C[Populate args members]
    C --> D[fork]
    D --> E{Process?}

    E -->|Parent| F[args remains owned by unique_ptr]
    F --> G[Close namespace FDs]
    G --> H[configure_user_namespace]
    H --> I[Function returns<br/>args auto-deleted]

    E -->|Child| J[args.release to args_ptr]
    J --> K[unshare namespaces]
    K --> L{PID namespace?}

    L -->|Yes| M[fork again]
    M --> N{Process?}
    N -->|Middle| O[waitpid inner child]
    O --> P[delete args_ptr]
    P --> Q[_exit]

    N -->|Inner| R[container_main args_ptr]
    R --> S[execvp<br/>no return]

    L -->|No| R
```

## State Management

```mermaid
stateDiagram-v2
    [*] --> creating: runtime create
    creating --> created: process forked
    created --> running: runtime start
    running --> paused: runtime pause
    paused --> running: runtime resume
    running --> stopped: runtime kill / process exit
    created --> stopped: runtime kill
    stopped --> [*]: runtime delete

    note right of creating
        - Create state directory
        - Create FIFO
        - Fork process
        - Setup cgroups
    end note

    note right of created
        - Process waiting on FIFO
        - Parent returned
        - State persisted
    end note

    note right of running
        - FIFO signaled
        - Container executing
        - Hooks executed
    end note

    note right of stopped
        - Process terminated
        - State preserved
        - Ready for delete
    end note
```

## Namespace Setup

```mermaid
graph TD
    subgraph "Namespace Creation"
        A[Parse config namespaces] --> B{Join existing?}
        B -->|Yes| C[open ns path]
        C --> D[store FD for setns]
        B -->|No| E[Add to unshare flags]
    end

    subgraph "Child Process"
        F[After fork] --> G[setns existing namespaces]
        G --> H[close FDs]
        H --> I[unshare new namespaces]
        I --> J{PID namespace?}
        J -->|Yes| K[fork again for PID 1]
        J -->|No| L[continue to container_main]
        K --> L
    end

    subgraph "Parent Process"
        M[After fork] --> N[close namespace FDs]
        N --> O[configure user namespace]
        O --> P[write uid_map/gid_map]
    end

    E --> F
    D --> F
```

## Mount Operations Order

```mermaid
graph TD
    A[chdir to rootfs] --> B[Process config mounts]
    B --> C[Mount each destination]
    C --> D[Apply propagation]
    D --> E[Process readonly_paths]
    E --> F[Bind mount paths]
    F --> G[Remount readonly]
    G --> H[pivot_root or chroot]
    H --> I[chdir /]
    I --> J[Mount /proc]
    J --> K[Apply masked_paths]
    K --> L[Mount tmpfs or /dev/null]
    L --> M[Remount rootfs readonly if needed]
```

## File Structure

```mermaid
graph TD
    subgraph "Source Files"
        Main["main.cpp<br/>(2019 lines)"]
        Config["src/runtime/config.cpp"]
        State["src/runtime/state.cpp"]
        Isolation["src/runtime/isolation.cpp"]
        Filesystem["src/runtime/filesystem.cpp"]
        Process["src/runtime/process.cpp"]
        Console["src/runtime/console.cpp"]
        Hooks["src/runtime/hooks.cpp"]
        Options["src/runtime/options.cpp"]
    end

    subgraph "Headers"
        ConfigH["include/runtime/config.h"]
        StateH["include/runtime/state.h"]
        IsolationH["include/runtime/isolation.h"]
        FilesystemH["include/runtime/filesystem.h"]
        ProcessH["include/runtime/process.h"]
        ConsoleH["include/runtime/console.h"]
        HooksH["include/runtime/hooks.h"]
        OptionsH["include/runtime/options.h"]
    end

    subgraph "External Dependencies"
        JSON["json.hpp<br/>nlohmann/json"]
    end

    Main --> Config
    Main --> State
    Main --> Isolation
    Main --> Filesystem
    Main --> Process
    Main --> Console
    Main --> Hooks
    Main --> Options

    Config --> ConfigH
    State --> StateH
    Isolation --> IsolationH
    Filesystem --> FilesystemH
    Process --> ProcessH
    Console --> ConsoleH
    Hooks --> HooksH
    Options --> OptionsH

    Config --> JSON
    State --> JSON
```

## Runtime State Directory

```mermaid
graph TD
    subgraph "State Directory: /run/runway/"
        Base["/run/runway/"]
        Container["&lt;container-id&gt;/"]
        StateFile["state.json"]
        FIFO["sync_fifo"]
        Events["events.log"]
    end

    Base --> Container
    Container --> StateFile
    Container --> FIFO
    Container --> Events

    StateFile -.-> |contains| StateData["id, pid, status,<br/>bundle, annotations"]
    Events -.-> |logs| EventData["state changes,<br/>errors, signals"]
```

## Key Data Structures

```mermaid
classDiagram
    class ContainerArgs {
        +vector~string~ process_args
        +vector~string~ process_env
        +string process_cwd
        +string sync_fifo_path
        +string rootfs_path
        +string hostname
        +bool rootfs_readonly
        +vector~MountConfig~ mounts
        +vector~string~ masked_paths
        +vector~string~ readonly_paths
        +uint32_t uid
        +uint32_t gid
    }

    class ContainerState {
        +string id
        +pid_t pid
        +string status
        +string bundle_path
        +string version
        +map~string,string~ annotations
        +to_json() string
        +from_json() ContainerState
    }

    class OCIConfig {
        +string ociVersion
        +ProcessConfig process
        +RootConfig root
        +string hostname
        +vector~MountConfig~ mounts
        +LinuxConfig linux
        +HooksConfig hooks
        +map~string,string~ annotations
    }

    class LinuxConfig {
        +vector~NamespaceConfig~ namespaces
        +vector~LinuxIDMapping~ uid_mappings
        +vector~LinuxIDMapping~ gid_mappings
        +ResourcesConfig resources
        +string cgroups_path
        +vector~string~ masked_paths
        +vector~string~ readonly_paths
    }

    OCIConfig *-- ProcessConfig
    OCIConfig *-- LinuxConfig
    OCIConfig *-- HooksConfig
    LinuxConfig *-- ResourcesConfig
```

## Error Handling & Fixes

```mermaid
graph TD
    subgraph "Fixed Issues"
        E1["Exit 139<br/>Segmentation Fault"]
        E2["PID File Parse Error"]
        E3["Cgroup Mount EBUSY"]
        E4["Masked Paths Failure"]
        E5["pivot_root Invalid Argument"]
        E6["docker kill Timeout"]
    end

    subgraph "Solutions"
        S1["Move args.release<br/>after fork"]
        S2["Remove endl<br/>from PID file"]
        S3["Ignore EBUSY<br/>for cgroup"]
        S4["Move after /proc mount<br/>Skip on error"]
        S5["Add bind mount<br/>before pivot_root"]
        S6["Remove waitpid<br/>in kill_container"]
    end

    E1 --> S1
    E2 --> S2
    E3 --> S3
    E4 --> S4
    E5 --> S5
    E6 --> S6
```
