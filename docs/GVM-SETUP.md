# Greenbone / GVM setup

FinVAP's vulnerability scanning uses **Greenbone Vulnerability Manager (GVM /
OpenVAS)**. You only need this for the GVM scan — `finvap <ip> --no-gvm` (nmap
discovery only) and `finvap <file.nessus>` (import) work without it.

```bash
sudo apt update && sudo apt install -y gvm gvm-tools
sudo gvm-setup        # syncs feeds (~1–3 hrs, several GB) + creates the admin user
sudo gvm-check-setup  # verify
sudo gvm-start
```

The `gvm-setup` feed sync is the slow part — **allow ~1–3 hours** (several GB of
NVT/SCAP/CERT data, network-dependent). It runs unattended, so start it and walk
away; don't scan until `finvap doctor` reports ready.

Then export the admin credentials `gvm-setup` printed:

```bash
export FINVAP_GVM_USER=admin
export FINVAP_GVM_PASS='<password-from-gvm-setup>'
```

Confirm readiness any time with `finvap doctor`.

---

## Troubleshooting: `gvm-start` fails (`gvmd.service` timeout / "Can't open PID file")

Almost always this is **PostgreSQL not actually running**. `gvmd` reads its DB
from the postgres cluster; if the cluster is down, `gvmd` exits immediately and
`gvmd.service` times out with:

```
gvmd.service: Can't open PID file '/run/gvmd/gvmd.pid' (yet?) ... No such file or directory
# and in /var/log/gvm/gvmd.log:
sql_open: PQconnectStart to 'gvmd' failed: connection to server on socket
"/var/run/postgresql/.s.PGSQL.5432" failed: No such file or directory
```

The catch: `systemctl status postgresql` can say **`active (exited)`** while the
real database (`postgresql@<ver>-main`) is **down** — that wrapper unit lies.
Check the actual cluster:

```bash
pg_lsclusters                                   # look for Status = down
```

**Fix** — start the versioned cluster, then GVM:

```bash
sudo systemctl start postgresql@<ver>-main      # e.g. postgresql@18-main (use your version)
# or, version-agnostic:
sudo pg_ctlcluster $(pg_lsclusters -h | awk '$4=="down"{print $1" "$2}') start
sudo gvm-start
```

**Stop it recurring** (the cluster wasn't coming up at boot) — enable the
versioned unit:

```bash
sudo systemctl enable postgresql@<ver>-main
```

If `gvmd` still fails after postgres is up, read the real reason in
`sudo tail -n 40 /var/log/gvm/gvmd.log` (a common one after an `apt upgrade` is a
pending DB migration: `sudo runuser -u _gvm -- gvmd --migrate`).
