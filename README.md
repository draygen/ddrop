# DraygenDrop

Simple LAN file transfer. Server runs on WSL, clients run on Mac, Windows, or Linux — no cloud, no accounts, no browser required.

## How it works

```
Mac / Windows  ──── HTTP ────▶  DraygenDrop Server (WSL)
                                       │
                                 ~/draygendrop/
```

Clients auto-discover the server via a UDP broadcast — no manual IP config needed after the first run.

## Server setup (WSL)

```bash
pip install flask
python3 server.py
```

Output:
```
  ┌──────────────────────────────────────────────────┐
  │              DraygenDrop Server                  │
  ├──────────────────────────────────────────────────┤
  │  Address     http://192.168.1.50:7474            │
  │  Drop dir    /home/user/draygendrop              │
  │  Discovery   UDP :7475                           │
  └──────────────────────────────────────────────────┘
```

Options:
```bash
python3 server.py --port 7474        # HTTP port (default: 7474)
python3 server.py --dir ~/drops      # storage directory
python3 server.py --udp 7475         # UDP discovery port
```

## Client setup

### Mac / Linux
```bash
chmod +x ddrop
./ddrop --discover          # find the server, save address
```

Or copy to PATH:
```bash
cp ddrop /usr/local/bin/ddrop
```

### Windows
```bat
ddrop.bat --discover
```
Or just: `python ddrop --discover`

## Client usage

```bash
ddrop photo.jpg report.pdf       # upload one or more files (globs work too)
ddrop *.log                        # upload all .log files
ddrop -l                           # list files on server
ddrop -g report.pdf                # download to current directory
ddrop -d old_file.zip              # delete from server
ddrop --discover                   # re-scan LAN for server
ddrop -s 192.168.1.50:7474         # set server address manually
ddrop --server-info                # show saved server address
```

The server address is saved to `~/.draygendrop` after `--discover` or `-s`, so you only need to do it once.

## Files

| File | Purpose |
|------|---------|
| `server.py` | DraygenDrop server (run on WSL) |
| `ddrop` | CLI client (Mac / Linux / WSL) |
| `ddrop.bat` | CLI client wrapper (Windows cmd) |
| `~/.draygendrop` | Saved server address (auto-created) |
| `~/draygendrop/` | Default drop directory on server |

## Network ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 7474 | TCP/HTTP | File transfer API |
| 7475 | UDP | LAN auto-discovery |

> **Windows firewall**: if clients can't reach the server, add an inbound rule for TCP 7474 and UDP 7475 on the Windows host, or run the server with `--port` on a port that's already allowed.
