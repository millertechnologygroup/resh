# System Information

This section covers tools for gathering information about your computer system in Resource Shell. These tools help you monitor system health, check resource usage, and understand how your system is performing.

## What This Section Covers

System information includes:
- **Hardware Details**: Information about your CPU, memory, and disk space
- **System Status**: How long your system has been running and current load
- **Resource Usage**: How much memory, CPU, and disk space are being used
- **Environment Settings**: System variables and configuration settings

## Available Tools

### system - Get System Information and Monitor Performance
The `system` handle provides comprehensive information about your computer's hardware, performance, and current status. It can tell you everything from how much memory you're using to how busy your CPU is.

**What it does:**
- Show overall system information (OS, kernel, hardware)
- Check system uptime and when it was last restarted
- Monitor CPU load and performance
- Display memory usage (RAM and swap space)
- Report disk space usage across all drives
- List environment variables and system settings

**Common workflows:**
- Check if your system is running out of memory
- Monitor CPU usage to find performance problems
- See how much disk space is available
- Get basic system details for troubleshooting
- Monitor system load to know when it's busy
- Check environment settings for applications

[Learn more about system monitoring →](system.md)

## Key Features

The system tool provides seven main types of information:

### System Overview (`info`)
Gets a complete picture of your system including operating system details, kernel version, CPU information, memory usage, and current load. This is like getting a health check for your entire computer.

### Uptime Information (`uptime`)
Shows how long your system has been running since the last restart and when it was booted. This helps you know if your system needs a restart or has been stable for a long time.

### Load Monitoring (`load`)
Tells you how busy your CPU is by showing load averages and the number of running processes. This helps you understand if your system is working hard or has plenty of capacity.

### Memory Usage (`memory`)
Shows how much RAM and swap space you're using, including details about buffers and cache. This helps you know if you need more memory or if programs are using too much.

### CPU Performance (`cpu`)
Reports CPU utilization, the number of cores, and processor topology. This helps you understand your computer's processing power and how it's being used.

### Disk Usage (`disk`)
Lists all mounted drives and shows how much space is used and available on each one. This helps you manage storage and avoid running out of disk space.

### Environment Variables (`env.list`)
Shows system environment variables that control how programs behave. This helps you check configuration settings and troubleshoot application problems.

## How System Monitoring Works

The system tool gathers information from various sources on Linux systems:
- **Filesystem Data**: Reads from `/proc` and `/sys` filesystems
- **System Calls**: Uses standard Linux system calls for accurate data
- **Real-time Sampling**: Takes measurements over time for accurate CPU usage
- **Safe Collection**: Automatically handles missing data and virtual environments

## Understanding the Output

All system information is returned in JSON format that's easy to read and use in scripts. The output includes:
- **Current Values**: Real-time measurements of system resources
- **Human-readable Summaries**: Easy-to-understand descriptions of the data
- **Percentage Values**: Usage shown as percentages for quick understanding
- **Historical Data**: Load averages and trend information
- **Warning Messages**: Alerts about potential issues or limitations

## Performance and Safety

The system tool is designed to be:
- **Fast**: Quick data collection that doesn't slow down your system
- **Safe**: Read-only operations that don't change anything
- **Accurate**: Reliable measurements you can trust for monitoring
- **Efficient**: Minimal impact on system performance
- **Secure**: Automatically hides sensitive information like passwords

## Common Use Cases

**Check System Health:**
```bash
system://.info
```

**Monitor Memory Usage:**
```bash
system://.memory
```

**See Disk Space:**
```bash
system://.disk
```

**Check System Load:**
```bash
system://.load
```

**Get Environment Variables:**
```bash
system://.env.list
```

## Getting Started

The system tool uses a simple URL-style syntax:
- `system://.info` - Get complete system overview
- `system://.memory` - Check memory usage
- `system://.disk` - See disk space usage
- `system://.load` - Monitor system load
- `system://.cpu` - Check CPU performance

All commands return detailed JSON output with both raw data and human-friendly summaries. You can use these commands in scripts to automate system monitoring or run them manually to check system status.

## Platform Support

- **Linux**: Full support for all features
- **Unix/macOS**: Basic features work (some Linux-specific data may not be available)
- **Windows**: Limited support - basic system information only
- **Virtual Environments**: Works in containers and WSL with appropriate warnings

The tool automatically detects your environment and provides the best information available for your platform.