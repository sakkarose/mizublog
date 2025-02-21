---
title: "Rootless Docker on Alpine Linux"
date: 2024-09-09T22:00:00+07:00
draft: false
categories:
  - project
tags:
  - docker
  - security
  - alpine linux
keywords:
  - docker
  - rootless docker
  - alpine linux
  - secure docker
---

I was trying out some open-source web application firewalls (WAFs), so I decided to set up a Docker virtual machine with strong security implementations and practices.

## Overview

I chose Alpine Linux for its lightweight nature and its foundation on musl. Since my primary use case was Docker, I wasn't particularly concerned about the potential drawbacks of musl. At the time of setting up this project, I used `Alpine Linux 3.20.2 virt`.

## Setting Up

### Alpine Linux

I won't delve too deeply into this aspect. Using `setup-alpine`, I configured DNS, installed the OS on sda/sys, and enabled the community repository.

After the initial setup, I created a cronjob for time synchronization. You can achieve this by simply creating a file at `/etc/periodic/hourly/` with the following content:

```
#!/bin/sh
ntpd -d -q -n -p uk.pool.ntp.org
```

Before setting up Docker, the next crucial step was to create an isolated user. Since I was aiming for a rootless Docker setup, I needed a non-root user for this purpose.

### Docker

I created a non-root user called `docker-user`. After installing Docker, I added this user to the Docker group.

```
apk update
apk add docker docker-compose
addgroup dockeruser docker
```

Next, I set up `newuidmap` and `newgidmap`, which are essential for using multiple UIDs/GIDs in the user namespace. For Alpine Linux, the relevant package is `shadow-uidmap`. You can install it with the following command: `apk add shadow-uidmap fuse-overlayfs iproute2`.

Afterward, I uncommented the line `rc_cgroup_mode='unified'` in `/etc/rc.conf` and proceeded to set up the UID/GID for Docker.

```
rc-update add cgroups && rc-service cgroups start
echo dockeruser:100000:65536 >/etc/subuid
echo dockeruser:100000:65536 >/etc/subgid
apk add docker docker-cli-compose curl
```

Then, I enabled the `ip_tables` module for Docker networking.

```
echo "ip_tables" >> /etc/modules
modprobe ip_tables
reboot
```

I logged in as the newly created non-root user and downloaded the rootless Docker installation script: `curl -fsSL https://get.docker.com/rootless -o rootless-docker-install.sh`. After verifying the script's contents, I ran the following command to install it: `sh -x rootless-docker-install.sh`.

Once the installation was complete, I created the init script `/etc/init.d/docker-rootless` with the following content (remember to replace dockeruser with your actual username):

```
#!/sbin/openrc-run

name=$RC_SVCNAME
description="Docker Application Container Engine (Rootless)"
supervisor="supervise-daemon"
command="/home/dockeruser/bin/dockerd-rootless.sh"
command_args=""
command_user="dockeruser"
supervise_daemon_args=" -e PATH=\"/home/dockeruser/bin:/sbin:/usr/sbin:$PATH\" -e HOME=\"/home/dockeruser\" -e XDG_RUNTIME_DIR=\"/home/dockeruser/.docker/run\""

reload() {
    ebegin "Reloading $RC_SVCNAME"
    /bin/kill -s HUP \$MAINPID
    eend $?
}
```

I then made it executable and enabled it to run at startup.

```
chmod +x /etc/init.d/docker-rootless
rc-update add docker-rootless
rc-service docker-rootless start
```

You can test your rootless Docker setup with these commands:

```
reboot
docker ps
docker run --rm hello-world
```

If you need to use privileged ports (below 1024) for Docker networking, you can expose them as root with the following. However, exercise caution: exposing privileged ports increases the risk of security vulnerabilities. Only do this if absolutely necessary, and implement additional security measures like restricting access to those ports with firewalls and only allowing trusted connections.

```
echo 'net.ipv4.ip_unprivileged_port_start=0' >> /etc/sysctl.conf
sysctl --system
```

### SSH

Since I connect to my machine over the internet, I needed to secure my SSH connections. I'll cover SSH and SFTP in detail in a later post.

## Maintaining

### Upgrading to a New Branch

First, back up your machine. To upgrade, you'll need to update the `/etc/apk/repositories` file. I used this command: `sed -i -e 's/v3\.20/v3\.21/g' /etc/apk/repositories`. Replace `v3.20` with your current version and `v3.21` with the target version. You can find the current stable version on the [Alpine Linux releases page](https://www.alpinelinux.org/releases/).

Then, update and upgrade your packages:

```
apk update
apk upgrade --available
```

## Troubleshooting

### Failed to create endpoint postgres on network bridge

* Full error output:

`docker: Error response from daemon: failed to create endpoint postgres on network bridge: failed to add the host (veth4ea851e) <=> sandbox (vethcd53b3f) pair interfaces: operation not supported.`

* Resolution: 

This error might occur after a recent kernel upgrade. Rebooting the machine should resolve it.

## What's Next

This post focused on setting up rootless Docker on Alpine Linux. If you face any issues or need troubleshooting assistance, you can find my contact information on [my about page](https://mizu.reisen/about/).

In my next blog post, I'll provide a comprehensive guide to secure SSH setup and discuss some self-hosted applications suitable for this lab machine.

## Resources

* [Docker Engine - Rootless mode](https://docs.docker.com/engine/security/rootless/)

* [Alpine Linux Wiki](https://wiki.alpinelinux.org/wiki/Main_Page)
