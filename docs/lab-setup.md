# Lab setup (Windows, 16 GB RAM)

```
┌──────────────────────── your Windows PC ─────────────────────────┐
│  Docker Desktop (WSL 2)                VirtualBox host-only net   │
│  ┌──────────────┐ ┌─────────┐          192.168.56.0/24            │
│  │ wazuh.manager│ │ indexer │  ◀─1514/1515─ web01 (Ubuntu)  .10  │
│  └──────────────┘ └─────────┘               kali (attacker) .20  │
│  ┌──────────────┐                                                 │
│  │  dashboard   │   vigil (python)  →  localhost:5050             │
│  └──────────────┘                                                 │
└───────────────────────────────────────────────────────────────────┘
```

## 1. Memory budget

16 GB is enough if you're deliberate about it:

| What | RAM |
|---|---|
| Wazuh (manager + indexer + dashboard) | ~5-6 GB |
| Ubuntu victim VM (`web01`) | 2 GB |
| Kali attacker VM | 2-3 GB (start it only for the attacks) |
| Windows itself | the rest |

Docker Desktop takes RAM through WSL 2. Cap it so Windows and the VMs keep
enough. Create `%UserProfile%\.wslconfig`:

```ini
[wsl2]
memory=8GB
```

Then run `wsl --shutdown` and restart Docker Desktop. `vigil.ps1` refuses to
start below 6 GB and warns below 8 GB.

## 2. Wazuh

Install [Docker Desktop](https://www.docker.com/products/docker-desktop/)
(WSL 2 backend, the default) and [Git for Windows](https://git-scm.com/),
then from the repo folder in PowerShell:

```powershell
.\setup\vigil.ps1 up
```

If PowerShell refuses to run the script (`running scripts is disabled`),
allow it for this session only:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
```

The first run downloads about 3 GB of images. When it prints *Wazuh is
running*, open <https://localhost> (accept the self-signed certificate) and
log in as `admin` / `SecretPassword`.

**After a reboot**, run `.\setup\vigil.ps1 up` again. It re-applies the
`vm.max_map_count` setting the indexer needs, which Docker Desktop's VM
forgets on restart. If the indexer container keeps restarting, that's
almost always why.

## 3. Lab network (VirtualBox)

1. VirtualBox → *File → Tools → Network Manager* → *Host-only Networks*:
   make sure one exists with the host at `192.168.56.1/24`.
2. Give each VM **two adapters**: NAT (internet, for installing packages)
   and Host-only (the lab network).
3. On the VMs, the host-only interface gets an address like `192.168.56.10`.

Docker Desktop publishes 1514/1515 on all of the PC's interfaces, so agents
reach Wazuh at **`192.168.56.1`**. If agents can't connect, allow the two
ports from the lab subnet only (PowerShell as Administrator):

```powershell
New-NetFirewallRule -DisplayName "Wazuh agents (lab)" -Direction Inbound `
  -Protocol TCP -LocalPort 1514,1515 -RemoteAddress 192.168.56.0/24 -Action Allow
```

## 4. Victim VM: `web01`

Ubuntu Server 24.04 with SSH and nginx, so it produces the same logs
Trellis reads:

```bash
sudo apt update && sudo apt install -y openssh-server nginx
# a deliberately weak account for the brute-force scenario (lab only!)
sudo adduser deploy          # password: something from a small wordlist, e.g. "sunshine"
sudo usermod -aG sudo deploy
```

Copy `agent/install-agent.sh` to the VM and run:

```bash
sudo ./install-agent.sh 192.168.56.1 web01
```

The agent should appear as **active** in Wazuh's dashboard (*Agents*)
within a minute.

> Never put this VM on a network you don't control. It has a weak password
> on purpose.

## 5. Attacker VM: Kali

Any recent Kali works; the scenarios only use tools it ships with (nmap,
nikto, gobuster, hydra, sqlmap, curl). It does **not** get an agent: it's
the outside attacker.

## 6. The Vigil dashboard

On Windows, with Python 3.10+:

```powershell
pip install -r requirements.txt
copy .env.example .env
notepad .env                  # set VIGIL_INDEXER_PASSWORD
python -m vigil check
python -m vigil serve
```

`check` tells you exactly what's wrong if it can't connect:

| Message | Fix |
|---|---|
| `can't reach the indexer` | Wazuh isn't running: `.\setup\vigil.ps1 status` |
| `rejected the username/password` | Wrong `VIGIL_INDEXER_PASSWORD` |
| `TLS error` | `VIGIL_CA_CERT` should point at `wazuh-docker\single-node\config\wazuh_indexer_ssl_certs\root-ca.pem` (the default), `VIGIL_TLS_HOSTNAME` should be `wazuh.indexer` |

## Passwords

Wazuh's defaults (`admin` / `SecretPassword`, and the API's
`wazuh-wui` password) are printed in every tutorial. Because `vigil.ps1`
binds the dashboard, indexer and API to localhost, nothing on your network
can reach them. Still, change them before you ever:

- open the dashboard to another machine, or
- run this anywhere other than your own PC.

Follow the **"Change the password of Wazuh users"** section of
[Wazuh's Docker deployment guide](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html),
then update `VIGIL_INDEXER_PASSWORD` in `.env`.
