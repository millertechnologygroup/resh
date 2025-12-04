# Filesystem & Storage

This section covers tools for working with files, folders, and storage systems on your computer. These tools help you manage your data, organize files, and work with different storage devices.

## What is Filesystem & Storage?

Filesystem and storage management involves working with the files and folders on your computer. This includes:

- **Managing files and folders** - Creating, reading, writing, and organizing your data
- **Working with compressed files** - Creating and extracting ZIP files, TAR files, and other archives
- **Managing storage devices** - Mounting drives, checking disk space, and resizing partitions
- **Creating backups** - Taking snapshots of important files and folders so you can restore them later

Think of it like being a librarian for your computer - organizing books (files) on shelves (folders), managing storage rooms (disks), and keeping backup copies of important books (snapshots).

## Available Tools

### [File Operations](file.md)
Work with individual files and directories. Read, write, copy, move, and check file properties. This is your basic toolkit for day-to-day file management.

**Use file operations when you need to:**
- Read or write text files
- Copy or move files between folders
- Check file sizes, dates, or permissions
- Create new directories
- Compare file contents

### [Archive Management](archive.md)
Create and work with compressed files like ZIP, TAR, and 7-Zip archives. Pack multiple files into smaller packages or extract files from existing archives.

**Use archives when you need to:**
- Compress files to save space
- Package multiple files into one file for easy sharing
- Extract files from ZIP or TAR downloads
- Create backups with compression
- Organize related files together

### [Filesystem Operations](fs.md)
Manage mounted storage devices and filesystems. Mount drives, check disk usage, resize partitions, and work with different types of storage systems.

**Use filesystem operations when you need to:**
- Mount USB drives or external storage
- Check how much disk space is available
- Resize partitions to make them bigger or smaller
- Work with different filesystem types (ext4, NTFS, etc.)
- Manage network storage

### [Snapshots](snapshot.md)
Create point-in-time copies of files and directories. Save important versions of your work that you can restore or compare later.

**Use snapshots when you need to:**
- Create backups of important files or projects
- Save different versions of your work
- Restore files to an earlier state
- Compare how files have changed over time
- Protect against accidental file loss

## Choosing the Right Tool

Here's a simple guide to help you pick the right tool:

- **For basic file tasks:** Use [File Operations](file.md)
- **For working with ZIP/TAR files:** Use [Archive Management](archive.md)
- **For managing drives and storage:** Use [Filesystem Operations](fs.md)
- **For backups and versioning:** Use [Snapshots](snapshot.md)

## Common Workflows

### Backing Up Your Work
1. Use [Snapshots](snapshot.md) to create a backup copy
2. Use [Archive Management](archive.md) to compress the backup
3. Use [File Operations](file.md) to move the archive to a safe location

### Organizing Downloaded Files
1. Use [Archive Management](archive.md) to extract downloaded ZIP files
2. Use [File Operations](file.md) to organize the extracted files into proper folders
3. Use [Snapshots](snapshot.md) to backup important extracted data

### Managing Storage Space
1. Use [Filesystem Operations](fs.md) to check available disk space
2. Use [Archive Management](archive.md) to compress large files
3. Use [File Operations](file.md) to clean up temporary files

## Getting Started

Each tool has its own documentation with examples and step-by-step instructions. Start with [File Operations](file.md) if you're new to filesystem management, as it covers the basics that other tools build upon.

Remember: always make backups of important data before making major changes to your filesystem or storage configuration. The [Snapshots](snapshot.md) tool is perfect for this!