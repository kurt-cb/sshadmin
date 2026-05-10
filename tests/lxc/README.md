# LXC Integration Tests

End-to-end tests that spin up real LXC containers and exercise the complete
sshadmin certificate workflow — including multi-CA group isolation.

---

## Container Topology

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Base containers (lxc_env fixture)                                      │
│                                                                         │
│   CAPP  (sshadmin-lxc-app)                                              │
│     Ubuntu 22.04 — Flask server, site CA, SQLite DB                    │
│     Completely isolated from the unit-test suite's in-memory DB         │
│                                                                         │
│   C1    (sshadmin-lxc-c1)                                               │
│     Ubuntu 22.04 — OpenSSH, primary origin node                        │
│     Alice/Bob/Carol keys + certs deployed here for outbound SSH         │
│                                                                         │
│   C2    (sshadmin-lxc-c2)                                               │
│     Ubuntu 22.04 — OpenSSH target, enrolled with site CA               │
│     sshd: TrustedUserCAKeys = site CA, no authorized_keys              │
│                                                                         │
│   CALPINE  (sshadmin-lxc-alpine)                                        │
│     Alpine 3 — Dropbear SSH server + OpenSSH client                    │
│     Tests cross-implementation interoperability                         │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│  Group isolation containers (group_env fixture, extends lxc_env)        │
│                                                                         │
│   C_ACCT   (sshadmin-lxc-acct)                                          │
│     Ubuntu 22.04 — sshd trusts ONLY the Accounting CA                  │
│     Only alice's cert (Accounting CA) grants access                     │
│                                                                         │
│   C_SALES  (sshadmin-lxc-sales)                                         │
│     Ubuntu 22.04 — sshd trusts ONLY the Sales CA                       │
│     Only bob's cert (Sales CA) grants access                            │
│                                                                         │
│   C_HR     (sshadmin-lxc-hr)                                            │
│     Ubuntu 22.04 — sshd trusts ONLY the HR CA                          │
│     Only carol's cert (HR CA) grants access                             │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│  Enrollment script containers (lxc_enroll_env fixture, extends lxc_env) │
│                                                                         │
│   CENROLL_UBUNTU  (sshadmin-lxc-enroll-ubuntu)                          │
│   CENROLL_ALPINE  (sshadmin-lxc-enroll-alpine)                          │
│     Enrolled via `sshadmin_add alice@<ip>` run from C1                  │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## CA Group Model

The group isolation tests use the Accounting / Sales / HR scenario:

| User  | Group      | Group CA        | Can reach   | Denied     |
|-------|------------|-----------------|-------------|------------|
| alice | Accounting | Accounting CA   | C_ACCT      | C_SALES, C_HR |
| bob   | Sales      | Sales CA        | C_SALES     | C_ACCT, C_HR  |
| carol | HR         | HR CA           | C_HR        | C_ACCT, C_SALES |

Each group container's `TrustedUserCAKeys` contains **only** that group's CA
public key.  A cert signed by the wrong CA is cryptographically rejected by
OpenSSH — no policy rules or sshadmin runtime checks are involved.

Identity files on C1 for group tests:

```
/home/<user>/.ssh/id_group          # copy of user's Ed25519 private key
/home/<user>/.ssh/id_group-cert.pub # cert signed by that user's group CA
```

The default `id_ed25519` / `id_ed25519-cert.pub` (site CA) are left unchanged
so that the basic C1→C2 tests continue to pass.

---

## Prerequisites

| Requirement | Check |
|-------------|-------|
| LXC / LXD   | `lxc version` |
| Default LXC profile with network | `lxc profile show default` |
| `images:ubuntu/22.04` image cached | `lxc image list images: ubuntu/22.04` |
| `images:alpine/3.21` image cached  | `lxc image list images: alpine/3.21` |
| `ssh-keygen` on the test host | `ssh-keygen -V` |
| Python 3.9+ with pytest | `pytest --version` |

---

## Running the Tests

### All LXC tests

```bash
cd /home/kgodwin/sshadmin
pytest tests/lxc -v -m lxc
```

### A single test file

```bash
pytest tests/lxc/test_wrong_group_deny.py -v
pytest tests/lxc/test_lxc_login_different_ip.py -v
```

### Only the group isolation tests

```bash
pytest tests/lxc/test_wrong_group_deny.py tests/lxc/test_lxc_login_different_ip.py -v
```

### Skip the slow enrollment script tests

```bash
pytest tests/lxc -v -m lxc --ignore=tests/lxc/test_sshadmin_add.py
```

### Leave containers running after the test run

Use `--keep-containers` when you want to inspect the live environment after
tests complete (or after a failure):

```bash
pytest tests/lxc -v --keep-containers
```

Containers remain in `RUNNING` state.  Clean them up manually when done:

```bash
lxc delete --force \
  sshadmin-lxc-app sshadmin-lxc-c1 sshadmin-lxc-c2 sshadmin-lxc-alpine \
  sshadmin-lxc-acct sshadmin-lxc-sales sshadmin-lxc-hr \
  sshadmin-lxc-enroll-ubuntu sshadmin-lxc-enroll-alpine
```

---

## Inspecting Running Containers

### List containers and IPs

```bash
lxc list sshadmin-lxc
```

### Open a shell in a container

```bash
lxc exec sshadmin-lxc-app -- bash
lxc exec sshadmin-lxc-c1  -- bash
```

### Tail the sshadmin Flask log

```bash
lxc exec sshadmin-lxc-app -- journalctl -u sshadmin -f
```

### Query the sshadmin database directly

```bash
lxc exec sshadmin-lxc-app -- python3 -c "
import sqlite3
conn = sqlite3.connect('/app/instance/sshadmin.db')
for row in conn.execute('SELECT id,username,is_admin FROM user'):
    print(row)
"
```

### Check TrustedUserCAKeys on a group host

```bash
# C_ACCT should show only the Accounting CA public key:
lxc exec sshadmin-lxc-acct -- cat /etc/ssh/group_ca.pub

# Compare with the Accounting CA stored in CAPP:
lxc exec sshadmin-lxc-app -- python3 -c "
import sqlite3
conn = sqlite3.connect('/app/instance/sshadmin.db')
row = conn.execute(\"SELECT ca_key_path FROM ca_group WHERE name='accounting'\").fetchone()
print(open(row[0]+'.pub').read().strip())
"
```

### Try an SSH connection manually

```bash
# From the test host, via LXC exec:
C1_IP=$(lxc list sshadmin-lxc-c1 --format json | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(next(a['address'] for iface in d[0]['state']['network'].values()
           for a in iface['addresses'] if a['family']=='inet' and not a['address'].startswith('127.')))
")
ACCT_IP=$(lxc list sshadmin-lxc-acct --format json | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(next(a['address'] for iface in d[0]['state']['network'].values()
           for a in iface['addresses'] if a['family']=='inet' and not a['address'].startswith('127.')))
")

# alice → C_ACCT using group cert (should succeed):
lxc exec sshadmin-lxc-c1 -- su - alice -c \
  "ssh -o BatchMode=yes -o StrictHostKeyChecking=yes \
       -o UserKnownHostsFile=/etc/ssh/ssh_known_hosts \
       -o IdentitiesOnly=yes \
       -i /home/alice/.ssh/id_group \
       alice@${ACCT_IP} echo hello"

# bob → C_ACCT using group cert (should fail — wrong CA):
lxc exec sshadmin-lxc-c1 -- su - bob -c \
  "ssh -o BatchMode=yes -o StrictHostKeyChecking=yes \
       -o UserKnownHostsFile=/etc/ssh/ssh_known_hosts \
       -o IdentitiesOnly=yes \
       -i /home/bob/.ssh/id_group \
       bob@${ACCT_IP} echo hello"
```

---

## Test File Descriptions

| File | What it tests |
|------|---------------|
| `test_registration.py` | Users registered, credentials exist, host keys stored, certs issued |
| `test_ssh_basic.py` | C1→C2 cert auth succeeds; bare key (no cert) rejected |
| `test_cert_expiry.py` | Expired user cert rejected by server; expired host cert rejected by client |
| `test_dropbear.py` | P-256 enrollment rejected; OpenSSH↔Dropbear interop; Alpine musl↔Ubuntu glibc |
| `test_sshadmin_add.py` | `sshadmin_add` script enrolls Ubuntu and Alpine targets; cert auth works after |
| `test_wrong_group_deny.py` | Accounting/Sales/HR CA isolation: 3 pass, 6 deny, site-CA always denied on group hosts |
| `test_lxc_login_different_ip.py` | Cert works from any source IP by default; source-address restriction enforced |

---

## Architecture Notes

### Why each test file is self-contained

Each test file imports only from `conftest.py` and uses the fixtures declared
there.  The fixtures are session-scoped: containers start once and persist for
the entire `pytest` session.  Tests within a session share the same live
containers but must not depend on execution order.

### Why group isolation is cryptographic, not policy-based

Each CA group has its own keypair generated by `ssh-keygen` at group-create
time (stored under `/app/ca_group_<name>_key` in CAPP).  A target host's
`TrustedUserCAKeys` file lists only that group's CA public key.  OpenSSH
verifies the signing CA before any account lookup or policy check.  No sshadmin
code runs during the SSH handshake — the enforcement is entirely in OpenSSH.

### Why users are removed from the default group in group_env

`_get_user_cert_ca_key()` returns the first active group membership (by
insertion order).  The `default` group is created at sshadmin startup and
auto-approves every user, so it has the lowest group ID.  Without removal,
every user's cert would be signed by the site CA (default group's CA = site CA),
defeating group isolation.  `group_env` removes alice/bob/carol from the
default group so each user's first active group is their department group.

### Default identity vs. group identity

The default `id_ed25519` / `id_ed25519-cert.pub` on C1 is signed by the **site
CA** and is used by the basic tests (C1→C2).  The group tests use
`id_group` / `id_group-cert.pub` (same private key, cert signed by the group
CA).  `test_wrong_group_deny.py` also verifies that the site-CA cert is rejected
by all group hosts — confirming that group isolation protects against users who
obtain a site-level cert through other means.
