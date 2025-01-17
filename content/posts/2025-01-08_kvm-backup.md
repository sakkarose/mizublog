---
title: "KVM Backup with virtnbdbackup"
date: 2025-01-08T19:00:00+07:00
draft: false
categories:
  - article
tags:
  - kvm
  - backup
keywords:
  - kvm
  - backup
  - libvirt
  - virtnbdbackup
---
Broadcom's acquisition of VMware has led to significant increases in licensing costs, making it difficult for small and medium-sized businesses (SMBs) to keep up. As a result, many are turning to open-source alternatives like libvirt KVM and Proxmox. Proxmox offers built-in backup solutions, and in this blog post, we'll dive deep into KVM backup using virtnbdbackup.

## Overview

We'll be using `virtnbdbackup` version 2.18 on a KVM host running `Ubuntu Server 22.04`.

Here is the workflow for the latest script:
1. Prepare by creating a backup directory and initializing variables.
2. For each domain, back up the data, verify the backup, and clean up old backups to meet retention policies.
3. Synchronize the backups to network storage.

## Setting up virtnbdbackup
Installing `virtnbdbackup`

```
wget https://github.com/abbbi/virtnbdbackup/releases/download/v2.18/virtnbdbackup_2.18-1_all.deb
apt install ./virtnbdbackup_2.18-1_all.deb
nano /etc/apparmor.d/usr.lib.libvirt.virt-aa-helper
```

Next, you'll need to allow the QEMU daemon to create a socket on AppArmor. To do this, add the following strings

```
/var/tmp/virtnbdbackup.* rw,
/var/tmp/backup.* rw,
```

To these files (they might not exist by default):

```
/etc/apparmor.d/usr.lib.libvirt.virt-aa-helper
/etc/apparmor.d/local/abstractions/libvirt-qemu
/etc/apparmor.d/local/usr.sbin.libvirtd
```

## Additional installation for VM

To ensure file system consistency during backup, `virtnbdbackup` freezes and thaws the filesystems within the domains. Therefore, it is necessary to install `qemu-guest-agent` on your running VMs.

For Ubuntu/Debian based systems:
```
apt update && apt -y install qemu-guest-agent
systemctl enable qemu-guest-agent
systemctl start qemu-guest-agent
```

For Red Hat based systems:
```
yum install -y qemu-guest-agent
systemctl enable qemu-guest-agent
systemctl start qemu-guest-agent
```

For Windows systems:
1. First, you need to get the latest VirtIO ISO driver from the [Fedora repository](https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/).
2. You can access the ISO file by mounting it into the Windows VMs.
3. On the VM, navigate to the mounted ISO and execute `virtio-win-gt-x64`.

## Writing the backup script

The full script can be found at [my github](https://github.com/sakkarose/oddly_specific_scripts/blob/main/virtnbdbackup-alldomain.sh). In case of any updates and improvements, I will update this post too.

### Configuration variables

I set up many variables at the start of the script so it's easier for anyone to understand and modify it.

- `ROOT_DIR`: Local backup directory
- `LOG_DIR`: Log file directory
- `UPTIME_KUMA_URL`: URL for Uptime Kuma notifications
- `RETENTION_PERIOD`: Backup retention period in weeks
- `COPY_TO_NETWORK`: Enable/disable network sync
- `RCLONE_REMOTE`: Rclone remote name
- `RCLONE_REMOTE_DIR`: Remote backup directory

Additionally, let's not forget to set the execute permission for the script with `chmod +x virtnbdbackup-alldomain.sh`.

### Backing up all domains

Using a for loop, I am backing up all the domains of the current host.

```
DOMAINS=$(virsh list --all --name)
for DOMAIN in $DOMAINS; do
...
    output=$(virtnbdbackup -d "$DOMAIN" -l auto -o "$DESTINATION_DIR/" 2>&1) 
    echo "$output" | tee -a "$LOG_FILE"
...
done
```

### Incremental backups

`virtnbdbackup` performs incremental backups with monthly retention by analyzing the target directory. If a full backup already exists, it will create an incremental backup. However, monthly retention doesn't suit the needs of SMBs, which typically prefer weekly full backups of single VMs to minimize cloud storage costs.

To address this, the script provides a new function.

```
get_week_number() {
    local date="$1"
    local week_number=$(date +%V --date="$date -$(date +%d -d "$date") days +1 day")
    echo $(( (week_number - 1) % 4 + 1 ))
}

DATE=$(date +%Y-%m-%d)
WEEK_NUMBER=$(get_week_number "$DATE")
```

This function separates the target folder for each domain by the week number of the current backup. It will create the target folder if it doesn't exist.

```
for DOMAIN in $DOMAINS; do
...
    DESTINATION_DIR="$ROOT_DIR/$DOMAIN/$(date +%Y)/$(date +%m)/$WEEK_NUMBER" 

    if [ ! -d "$DESTINATION_DIR" ]; then
        echo "[$(date +'%Y-%m-%d %H:%M:%S')] Creating directory for domain: $DOMAIN" >> "$LOG_FILE" 
        mkdir -p "$DESTINATION_DIR"
    fi
...
done
```

Retention (by week) is set by the `RETENTION_PERIOD` variable in the script's configuration section. After the backup and verification process, the script checks for backups outside the retention period and removes them.

```
    current_week=$(date +%V)
    cutoff_week=$(( current_week - RETENTION_PERIOD ))

    find "$ROOT_DIR/$DOMAIN" -mindepth 1 -type d -mtime +$((RETENTION_PERIOD * 7)) -print0 | while IFS= read -r -d '' dir; do
        echo "[$(date +'%Y-%m-%d %H:%M:%S')] Removing old backup directory: $dir" >> "$LOG_FILE"
        rm -rf "$dir"
    done
```

### Backup verification

I'm using `virtnbdbackup`'s feature to verify the backup, making sure that it is usable in case of data loss.

```
    verify_output=$(virtnbdrestore -i "$DESTINATION_DIR" -o verify 2>&1)
    echo "$verify_output" | tee -a "$LOG_FILE"
```

### Log

I want to ensure system administrators can easily troubleshoot problems. Therefore, I'm outputting the `LOG_FILE` to the `LOG_DIR` directory, which is located beside the `ROOT_DIR` directory where I store backups.

Additionally, I've set log retention.

```
if [ $(date +%d) -eq "01" ]; then
    mv "$LOG_FILE" "$LOG_FILE.$(date +%Y%m%d%H%M%S)"
    touch "$LOG_FILE"
fi
```

### Uptime Kuma notification

You are not going to do cat and grep on the log daily to check the backup results, right? Yes, this is why I'm adding Uptime Kuma push notifications.

Currently, I have set push notifications in Uptime Kuma for:
- Backup status
- Verification status (failed only)
- Network backup synchronization status
- Cronjob status

### Cron setup

I automate daily backup runs with cron. The script is called by a cron wrapper script. I use a wrapper so I can track the cron job status with Uptime Kuma, separated from the `virtnbdbackup` commands.

```
#!/bin/bash

UPTIME_KUMA_URL='https://uptime.mizu.reisen/api/push/Y80kVEn7Os'

log_message() {
    local message="$1"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $message" >> /home/backup-str/cron.log
}

log_message "Running cronjob."

/home/backup-str/daily-backup.sh

# Check the exit code
if [[ $? -eq 0 ]]; then
    curl -fsS -m 10 --retry 5 -o /dev/null "$UPTIME_KUMA_URL?status=up&msg=Cronjob%20successful"
    log_message "Cronjob done successfully."
else
    curl -fsS -m 10 --retry 5 -o /dev/null "$UPTIME_KUMA_URL?status=down&msg=Cronjob%20failed"
    log_message "Cronjob failed."
fi
```
Then, I simply run `crontab -e` and configure this script with the run schedule time `0 0 * * * /home/backup-scripts/wrapper_script.sh`

### Synchronize backup to network storage with rclone

Working for a backup service provider has really helped me learn a lot. One of the key things I learned is the 3-2-1 backup rule.

Therefore, I  create a backup copy (using `rclone sync`) of the current backup directory after retention cleanup and send it to a network storage device. This copy is later replicated to an off-site storage location.

To implement this, I first need to set up the network storage.

```
cd /home/hoangdt
mkdir kvm-backupcopy
chown hoangdt kvm-backupcopy
chmod 700 kvm-backupcopy
```

Then, on the KVM host, I will set up an rclone remote using rclone config. You can use an account or public key for authentication.

I will not go into too much detail about this, as I will cover SSH in general later.

## What's next

This script is currently in use in a lab KVM environment, so there may still be bugs and issues. If you encounter any problems or need help with troubleshooting or improvements, you can find my contact information on [my about page](https://mizu.reisen/about/).

In the next blog post, we'll explore KVM native backup scripting.

## Resources

https://github.com/abbbi/virtnbdbackup

https://rclone.org/sftp/

https://rclone.org/commands/rclone_sync/