# The Sniper of eBPF deep monitoring tool
<img src="intro/sniper-intro.PNG" alt="INTRO" width="600" height="1000">

- Name Sniper
- Author: faruk-guler
- Version: 0.2

## Requirements
```powershell
Debian:
sudo apt update
sudo apt install -y python3-bpfcc bpfcc-tools linux-headers-$(uname -r)

RHEL:
sudo dnf update
sudo dnf install -y bcc-tools python3-bcc kernel-devel-$(uname -r)
```

## Usage
```powershell
sudo python3 sniper.py
sudo python3 sniper.py --log-dir /dir
sudo python3 sniper.py --format json
sudo python3 sniper.py --no-cmd
```

## Log Read
```powershell
tail -f outbound-dump.log
tail -f inbound-dump.log
grep curl outbound-dump.log
grep ":443" outbound-dump.log
sort outbound-dump.log | awk '{print $4}' | sort | uniq -c | sort -rn | head
```

## Features
- Monitoring outbound TCP connections.
- Monitoring inbound TCP connections.
- Monitoring IPv4 connections.
- Monitoring IPv6 connections.
- Tracking the initiation of TCP connections.
- Tracking accepted TCP connections.
- Detecting the local IP address.
- Detecting the remote IP address.
- Recording the local port.
- Recording the remote port.
- Determining the direction of the connection.
- Recording the connection timestamp.
- Displaying local and remote addresses separately.
- Recording PID information for the connection.
- Recording the process name.
- Detecting the Linux username.
- Recording UID information.
- Reading the process command line via /proc/PID/cmdline.
- Associating processes with network connections.
- Recording local processes that do not accept incoming data.
- Resolving hostnames via DNS.
- Monitoring the getaddrinfo() function.
- Collecting OpenSSL SNI information.
- Monitoring the SSL_set_tlsext_host_name() function.
- Mapping hostname information to PIDs.
- Recording hostname information obtained from DNS.
- Recording hostname information from SNI data.
- Hostname caching system.
- 20-second hostname cache duration.
- Clearing stale cache entries.
- Appending hostname information to terminal output records.
- Disabling hostname analysis using the --no-host flag.

