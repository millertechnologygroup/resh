# Process & Service Management

This section covers tools for managing running programs and system services in Resource Shell. These tools help you control processes, schedule tasks, and manage system services.

## What This Section Covers

Process and service management includes:
- **Process Control**: Managing running programs (sending signals, changing priority, monitoring output)
- **Task Scheduling**: Setting up automated tasks that run at specific times
- **Service Management**: Starting, stopping, and configuring system services

## Available Tools

### cron - Schedule Automated Tasks
The `cron` handle lets you create and manage scheduled tasks. You can set up jobs to run at specific times using either traditional Unix cron or modern systemd timers.

**What it does:**
- List all scheduled tasks on your system
- Add new tasks with custom schedules
- Remove tasks you don't need anymore
- Enable or disable tasks temporarily
- Works with both cron jobs and systemd timers

**Common workflows:**
- Daily backups that run automatically
- Regular system maintenance tasks
- Monitoring jobs that check system health
- Cleanup tasks that remove old files

[Learn more about cron →](cron.md)

### proc - Control Running Processes
The `proc` handle gives you control over running programs on your system. You can send signals to processes, change their priority, and monitor their output.

**What it does:**
- Send signals to processes (stop, restart, pause, resume)
- Change process priority levels
- Monitor process output logs
- Set resource limits for processes
- Check process status and information

**Common workflows:**
- Stop misbehaving programs
- Pause and resume tasks
- Give important programs higher priority
- Monitor program output for debugging
- Set memory or CPU limits for programs

[Learn more about proc →](proc.md)

### svc - Manage System Services
The `svc` handle controls system services like web servers, databases, and background programs. It works with different service managers including systemd and OpenRC.

**What it does:**
- Start and stop system services
- Check service status and health
- Configure services to start at boot
- Reload service configurations
- View service logs and history

**Common workflows:**
- Start web servers and databases
- Set up services to start automatically
- Restart services after configuration changes
- Check why a service isn't working
- Prevent unwanted services from starting

[Learn more about svc →](svc.md)

## How These Tools Work Together

These tools are designed to work together for complete system management:

1. **Use cron** to schedule regular tasks like backups or system checks
2. **Use proc** to control and monitor the processes that run those tasks
3. **Use svc** to manage the system services that support your applications

For example, you might:
- Use `svc` to ensure your database service starts at boot
- Use `cron` to schedule daily database backups
- Use `proc` to monitor the backup process and adjust its priority

## Getting Started

Each tool uses a simple URL-style syntax:
- `cron://local.list` - Show all scheduled tasks
- `proc://1234.status` - Check status of process 1234
- `svc://apache2.status` - Check if Apache web server is running

All tools return results in JSON format that's easy to read and use in scripts. Most operations include helpful error messages when something goes wrong.

## Platform Support

- **Linux**: Full support for all tools
- **Unix/macOS**: Most features work (systemd-specific features may not be available)
- **Windows**: Limited support - some features may not work

Each tool documentation includes specific platform compatibility information.