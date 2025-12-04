# svc Handle Documentation

The svc (service) handle lets you control and get info about system services. It works with different service managers like systemd, OpenRC, and others.

## Basic Usage

Use this format to run svc commands:
```
resh 'svc://[service-name].[verb]'
```

The service-name is the name of the service you want to work with. The verb is the action you want to do.

## Supported Verbs

### status

Gets current information about a service.

**What it does:** Shows if the service is running, when it started, and other details.

**Example:**
```bash
resh 'svc://dbus.status'
```

**Output:** JSON with service info including:
- `"backend"`: The service manager being used (like "systemd")
- `"active_state"`: Whether service is active
- `"sub_state"`: More detailed state info
- `"timestamps"`: When service started, stopped, etc.
- `"pid"`: Process ID if running

### start

Starts a service that is not running.

**What it does:** Tells the service manager to start the service.

**Example:**
```bash
resh 'svc://apache2.start'
```

### stop

Stops a running service.

**What it does:** Tells the service manager to stop the service. You can add options for force stopping or setting a timeout.

**Example:**
```bash
resh 'svc://apache2.stop'
```

**Options:**
- `--force`: Force stop the service
- `--timeout`: How long to wait before giving up

### restart

Stops and then starts a service.

**What it does:** Restarts the service by stopping it first, then starting it again.

**Example:**
```bash
resh 'svc://nginx.restart'
```

### reload

Reloads a service's config without stopping it.

**What it does:** Tells the service to reload its settings. The service keeps running but picks up new settings.

**Example:**
```bash
resh 'svc://nginx.reload'
```

### enable

Sets a service to start automatically when the system boots.

**What it does:** Configures the service to start by itself when the computer starts up.

**Example:**
```bash
resh 'svc://dbus.enable'
```

### disable

Stops a service from starting automatically when the system boots.

**What it does:** Configures the service so it won't start by itself when the computer starts up.

**Example:**
```bash
resh 'svc://dbus.disable'
```

### mask

Completely prevents a service from being started.

**What it does:** Blocks the service so it can't be started at all, even manually.

**Example:**
```bash
resh 'svc://dbus.mask'
```

### unmask

Removes the block on a service so it can be started again.

**What it does:** Removes the mask so the service can be started normally.

**Example:**
```bash
resh 'svc://dbus.unmask'
```

### is-enabled

Checks if a service is set to start automatically.

**What it does:** Tells you whether the service will start by itself when the system boots.

**Example:**
```bash
resh 'svc://dbus.is-enabled'
```

**Output:** JSON with:
- `"enabled"`: true or false

### wait

Waits for a service to reach a specific state.

**What it does:** Waits until the service gets to the state you want (like "active" or "inactive").

**Example:**
```bash
resh 'svc://apache2.wait' --state=active --timeout=30
```

**Options:**
- `--state`: The state to wait for
- `--timeout`: How long to wait before giving up

### logs

Shows recent log messages from a service.

**What it does:** Gets the latest log entries for the service from the system logs.

**Example:**
```bash
resh 'svc://nginx.logs'
```

**Options:**
- `--lines`: Number of log lines to show
- `--follow`: Keep watching for new logs

### scale

Changes the number of running instances of a service.

**What it does:** For services that support it, changes how many copies are running.

**Example:**
```bash
resh 'svc://myapp@.scale' --instances=3
```

**Options:**
- `--instances`: Number of service instances to run

## Service Managers

The svc handle works with these service managers:

- **systemd**: Most modern Linux systems
- **OpenRC**: Alpine Linux and some others
- **Generic**: Basic service scripts

The handle automatically detects which service manager your system uses.

## Error Handling

If a service doesn't exist or an action fails, you'll get an error message in JSON format. Common errors include:

- Service not found
- Permission denied
- Service manager not available
- Invalid options

## Examples by Use Case

**Check if a web server is running:**
```bash
resh 'svc://apache2.status'
```

**Start a database service:**
```bash
resh 'svc://mysql.start'
```

**Make sure a service starts at boot:**
```bash
resh 'svc://ssh.enable'
```

**Watch service logs in real time:**
```bash
resh 'svc://nginx.logs' --follow=true
```

**Restart a service and wait for it to be ready:**
```bash
resh 'svc://app.restart'
resh 'svc://app.wait' --state=active
```