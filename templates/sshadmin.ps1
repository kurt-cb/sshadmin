#Requires -Version 5.1
<#
.SYNOPSIS
    sshadmin.ps1 — SSH certificate management for sshadmin (Windows/PowerShell edition)

.DESCRIPTION
    Run on your CURRENT Windows machine to enroll or manage a remote machine.
    Requires OpenSSH for Windows (ssh, ssh-keygen must be in PATH).

    Commands:
      .\sshadmin.ps1 [opts] user@host              Enroll a new host
      .\sshadmin.ps1 update [opts] user@host       Renew expiring user cert on remote
      .\sshadmin.ps1 updatehost [opts] user@host   Renew expiring host cert (needs sudo on remote)
      .\sshadmin.ps1 alias [opts] user@host        Register alias, re-issue host cert
      .\sshadmin.ps1 update_cert [opts] user@host  Re-issue cert with all stored aliases

.EXAMPLE
    .\sshadmin.ps1 alice@newserver.example.com
    .\sshadmin.ps1 update alice@server1.example.com
    .\sshadmin.ps1 -Force updatehost alice@server1.example.com
    .\sshadmin.ps1 alias alice@192.168.1.100
    .\sshadmin.ps1 update_cert alice@server1.example.com
#>

param(
    [Parameter(ValueFromRemainingArguments)]
    [string[]]$Positional = @(),
    [Alias('u')][string]$User  = '',
    [Alias('d')][int]   $Days  = 365,
    [Alias('f')][switch]$Force,
    [Alias('h')][switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Configuration (set by sshadmin server at download time) ──────────────────
$SSHADMIN_HOST     = "{{ ssh_host }}"
$SSHADMIN_SSH_PORT = "{{ ssh_port }}"
$SSHADMIN_USER     = if ($User) { $User } else { $env:USERNAME }
$VALID_DAYS        = $Days
$RENEW_THRESHOLD   = 30
$FORCE_RENEW       = $Force.IsPresent

# ── Argument parsing ──────────────────────────────────────────────────────────

function Show-Usage {
    Write-Host @"
sshadmin.ps1 — manage SSH certificates via sshadmin (Windows edition)
Run on your CURRENT (enrolled) machine to operate on a remote machine.

Commands:
  .\sshadmin.ps1 [opts] user@host                Enroll a new host
  .\sshadmin.ps1 update [opts] user@host         Renew expiring user cert on remote
  .\sshadmin.ps1 updatehost [opts] user@host     Renew expiring host cert (needs sudo)
  .\sshadmin.ps1 alias [opts] user@host          Register alias, re-issue host cert
  .\sshadmin.ps1 update_cert [opts] user@host    Re-issue cert with all stored aliases

Options:
  -User USER    Your sshadmin username (default: `$env:USERNAME)
  -Days DAYS    Certificate validity in days (default: 365)
  -Force        Force renewal even if cert is not near expiry
  -Help         Show this help

Examples:
  .\sshadmin.ps1 alice@newserver.example.com
  .\sshadmin.ps1 update alice@server1.example.com
  .\sshadmin.ps1 -Force updatehost alice@server1.example.com
  .\sshadmin.ps1 alias alice@192.168.1.100
  .\sshadmin.ps1 update_cert alice@server1.example.com
"@
}

if ($Help) { Show-Usage; exit 0 }

# Detect optional subcommand as first positional
$SUBCOMMAND = 'add'
$args_list = [System.Collections.Generic.List[string]]::new($Positional)
if ($args_list.Count -gt 0 -and $args_list[0] -in @('update','updatehost','alias','update_cert')) {
    $SUBCOMMAND = $args_list[0]
    $args_list.RemoveAt(0)
}

if ($args_list.Count -ne 1) {
    Show-Usage
    exit 1
}

$TARGET = $args_list[0]
if ($TARGET -match '^([^@]+)@(.+)$') {
    $REMOTE_USER = $Matches[1]
    $REMOTE_HOST = $Matches[2]
} else {
    $REMOTE_USER = $env:USERNAME
    $REMOTE_HOST = $TARGET
    $TARGET      = "$($env:USERNAME)@$TARGET"
}

# ── Dependency check ─────────────────────────────────────────────────────────

foreach ($tool in @('ssh','ssh-keygen')) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        Write-Error "Required tool '$tool' not found.`nInstall OpenSSH: Settings > Optional Features > OpenSSH Client"
        exit 1
    }
}

# ── Helpers ───────────────────────────────────────────────────────────────────

function Die([string]$msg) {
    Write-Error "ERROR: $msg"
    exit 1
}

function Info([string]$msg) {
    Write-Host "[sshadmin] $msg"
}

function ConvertTo-B64([string]$s) {
    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s))
}

function ConvertFrom-B64([string]$s) {
    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s))
}

function Get-JsonField([string]$json, [string]$field) {
    try {
        $obj = $json | ConvertFrom-Json
        $val = $obj.$field
        return if ($null -eq $val) { '' } else { [string]$val }
    } catch { return '' }
}

# Run a sh script on the remote machine by piping it to ssh.
# Returns a hashtable with ExitCode and Output.
function Invoke-RemoteSh {
    param([string]$SshTarget, [string]$Script, [switch]$AcceptNew)
    $opts = @('-o', 'BatchMode=yes')
    if ($AcceptNew) { $opts += @('-o', 'StrictHostKeyChecking=accept-new') }
    else            { $opts += @('-o', 'StrictHostKeyChecking=yes') }

    $enc  = [Text.Encoding]::UTF8
    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo = [System.Diagnostics.ProcessStartInfo]@{
        FileName               = 'ssh'
        Arguments              = ($opts + @($SshTarget, 'sh')) -join ' '
        RedirectStandardInput  = $true
        RedirectStandardOutput = $true
        RedirectStandardError  = $true
        UseShellExecute        = $false
        StandardInputEncoding  = $enc
        StandardOutputEncoding = $enc
    }
    $null = $proc.Start()
    $proc.StandardInput.Write($Script)
    $proc.StandardInput.Close()
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    return @{
        ExitCode = $proc.ExitCode
        Output   = ($stdout + $stderr).Trim()
    }
}

# Send a command to the sshadmin SSH server.
function Invoke-SshadminCmd([string]$cmd) {
    $output = & ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new `
                    -p $SSHADMIN_SSH_PORT `
                    "${SSHADMIN_USER}@${SSHADMIN_HOST}" $cmd 2>&1
    return @{ ExitCode = $LASTEXITCODE; Output = ($output -join "`n").Trim() }
}

# Build a JSON payload with valid_days + connect_host injected, encoded as base64.
function Build-Payload([string]$json) {
    $obj = $json | ConvertFrom-Json
    # Add-Member -Force overwrites if already present
    $obj | Add-Member -NotePropertyName 'valid_days'    -NotePropertyValue ([int]$VALID_DAYS) -Force
    $obj | Add-Member -NotePropertyName 'connect_host'  -NotePropertyValue $REMOTE_HOST      -Force
    return ConvertTo-B64(($obj | ConvertTo-Json -Compress -Depth 5))
}

# Remove an sshadmin block from ~/.ssh/config by marker name.
function Remove-SshConfigBlock([string]$configPath, [string]$marker) {
    if (-not (Test-Path $configPath)) { return }
    $lines   = Get-Content $configPath -Raw
    if (-not $lines) { return }
    # Remove the block between BEGIN <marker> and END <marker>
    $escaped = [Regex]::Escape($marker)
    $pattern = "(?m)^# sshadmin:BEGIN $escaped\r?\n.*?^# sshadmin:END $escaped\r?\n?"
    $lines   = [Regex]::Replace($lines, $pattern, '', [System.Text.RegularExpressions.RegexOptions]::Singleline)
    Set-Content $configPath $lines.TrimEnd() -NoNewline
}

# ── Update subcommand ─────────────────────────────────────────────────────────

function Invoke-Update {
    Info "Checking user cert on ${REMOTE_HOST}..."

    $findKeyScript = @'
USER_KEY=""
USER_KEY_FILE="$HOME/.ssh/id_sshadmin"
for _c in "$HOME/.ssh/id_sshadmin.pub" "$HOME/.ssh/id_sshadmin_ecdsa_521.pub" "$HOME/.ssh/id_sshadmin_ed25519.pub"; do
    [ -f "$_c" ] || continue
    _kt=$(awk '{print $1}' < "$_c")
    case "$_kt" in ecdsa-sha2-nistp521|ecdsa-sha2-nistp384|ssh-ed25519)
        USER_KEY=$(cat "$_c"); USER_KEY_FILE="${_c%.pub}"; break ;; esac
done
if [ -z "$USER_KEY" ] && [ -d "$HOME/.ssh" ]; then
    for _pub in "$HOME"/.ssh/*.pub; do
        [ -f "$_pub" ] || continue
        case "$_pub" in *-cert.pub) continue ;; esac
        _kt=$(awk '{print $1}' < "$_pub")
        case "$_kt" in ecdsa-sha2-nistp521|ecdsa-sha2-nistp384|ssh-ed25519)
            USER_KEY=$(cat "$_pub"); USER_KEY_FILE="${_pub%.pub}"; break ;; esac
    done
fi
python3 -c "import sys,json; u,f=sys.argv[1:]; print(json.dumps({'user_key':u,'user_key_file':f}))" "$USER_KEY" "$USER_KEY_FILE" 2>/dev/null \
    || printf '{"user_key":"%s","user_key_file":"%s"}\n' "$USER_KEY" "$USER_KEY_FILE"
'@

    $r = Invoke-RemoteSh -SshTarget $TARGET -Script $findKeyScript -AcceptNew
    if ($r.ExitCode -ne 0) { Die "Could not query remote key info: $($r.Output)" }

    $remoteUserKey     = Get-JsonField $r.Output 'user_key'
    $remoteUserKeyFile = Get-JsonField $r.Output 'user_key_file'
    if (-not $remoteUserKey) { Die "No suitable SSH key on ${REMOTE_HOST}. Run '.\sshadmin.ps1 $TARGET' first." }

    $certPath = "${remoteUserKeyFile}-cert.pub"
    $chkScript = @"
if [ ! -f '$certPath' ]; then echo -1; exit 0; fi
python3 - '$certPath' <<'PY' 2>/dev/null || echo 0
import sys,subprocess,datetime,re
out=subprocess.check_output(['ssh-keygen','-L','-f',sys.argv[1]],text=True)
m=re.search(r'Valid:.*?to\s+(\d{4}-\d{2}-\d{2})',out)
if not m: print(-1)
else:
    exp=datetime.datetime.strptime(m.group(1),'%Y-%m-%d').date()
    print(max(0,(exp-datetime.date.today()).days))
PY
"@
    $cr = Invoke-RemoteSh -SshTarget $TARGET -Script $chkScript -AcceptNew
    $daysLeft = if ($cr.ExitCode -eq 0) { [int]($cr.Output.Trim()) } else { -1 }
    Info "User cert days remaining: $daysLeft"

    if (-not $FORCE_RENEW -and $daysLeft -gt $RENEW_THRESHOLD) {
        Info "User cert valid for $daysLeft more days (threshold: $RENEW_THRESHOLD). No renewal needed. Use -Force to override."
        exit 0
    }

    $payload = ConvertTo-B64(("{""user"":""{0}"",""user_key"":""{1}"",""valid_days"":{2}}" -f $REMOTE_USER, $remoteUserKey.Replace('"','\"'), $VALID_DAYS))
    $sr = Invoke-SshadminCmd "renew_user_cert $payload"
    if ($sr.ExitCode -ne 0) { Die "sshadmin renewal failed: $($sr.Output)" }

    $userCert    = Get-JsonField $sr.Output 'user_cert'
    if (-not $userCert) { Die "sshadmin returned no user_cert: $($sr.Output)" }

    $certB64    = ConvertTo-B64 $userCert
    $keyFileB64 = ConvertTo-B64 $remoteUserKeyFile
    $installScript = @"
USER_CERT=`$(printf '%s' '$certB64' | base64 -d)
USER_KEY_FILE=`$(printf '%s' '$keyFileB64' | base64 -d)
mkdir -p "`$HOME/.ssh"; chmod 700 "`$HOME/.ssh"
CERT_FILE="`${USER_KEY_FILE}-cert.pub"
printf '%s\n' "`$USER_CERT" > "`$CERT_FILE"
chmod 644 "`$CERT_FILE"
echo "User cert installed at `$CERT_FILE"
"@
    $ir = Invoke-RemoteSh -SshTarget $TARGET -Script $installScript -AcceptNew
    if ($ir.ExitCode -ne 0) { Die "Failed to install cert: $($ir.Output)" }
    Write-Host $ir.Output
    Info "User cert renewed on ${REMOTE_HOST}."
}

# ── Updatehost subcommand ─────────────────────────────────────────────────────

function Invoke-UpdateHost {
    Info "Checking host cert on ${REMOTE_HOST}..."
    $certPath = "/etc/ssh/ssh_host_sshadmin_ecdsa_key-cert.pub"
    $chkScript = @"
if [ ! -f '$certPath' ]; then echo -1; exit 0; fi
python3 - '$certPath' <<'PY' 2>/dev/null || echo 0
import sys,subprocess,datetime,re
out=subprocess.check_output(['ssh-keygen','-L','-f',sys.argv[1]],text=True)
m=re.search(r'Valid:.*?to\s+(\d{4}-\d{2}-\d{2})',out)
if not m: print(-1)
else:
    exp=datetime.datetime.strptime(m.group(1),'%Y-%m-%d').date()
    print(max(0,(exp-datetime.date.today()).days))
PY
"@
    $cr = Invoke-RemoteSh -SshTarget $TARGET -Script $chkScript -AcceptNew
    $daysLeft = if ($cr.ExitCode -eq 0) { [int]($cr.Output.Trim()) } else { -1 }
    Info "Host cert days remaining: $daysLeft"

    if (-not $FORCE_RENEW -and $daysLeft -gt $RENEW_THRESHOLD) {
        Info "Host cert valid for $daysLeft more days (threshold: $RENEW_THRESHOLD). Use -Force to override."
        exit 0
    }

    $hkr = Invoke-RemoteSh -SshTarget $TARGET -Script @'
sudo cat /etc/ssh/ssh_host_sshadmin_ecdsa_key.pub 2>/dev/null || echo ''
hostname -f 2>/dev/null || hostname
'@ -AcceptNew
    $lines    = $hkr.Output -split "`n"
    $hostKey  = $lines[0].Trim()
    $fqdn     = if ($lines.Count -gt 1) { $lines[1].Trim() } else { $REMOTE_HOST }
    if (-not $hostKey) { Die "No host key at /etc/ssh/ssh_host_sshadmin_ecdsa_key.pub on ${REMOTE_HOST}." }

    $payload = ConvertTo-B64(("{""hostname"":""{0}"",""host_key"":""{1}"",""valid_days"":{2}}" -f $fqdn, $hostKey.Replace('"','\"'), $VALID_DAYS))
    $sr = Invoke-SshadminCmd "renew_host_cert $payload"
    if ($sr.ExitCode -ne 0) { Die "sshadmin host renewal failed: $($sr.Output)" }

    $hostCert = Get-JsonField $sr.Output 'host_cert'
    if (-not $hostCert) { Die "sshadmin returned no host_cert: $($sr.Output)" }

    $certB64 = ConvertTo-B64 $hostCert
    $installScript = @"
HOST_CERT=`$(printf '%s' '$certB64' | base64 -d)
TARGET_CERT=/etc/ssh/ssh_host_sshadmin_ecdsa_key-cert.pub
printf '%s\n' "`$HOST_CERT" | sudo tee "`$TARGET_CERT" > /dev/null
sudo chmod 644 "`$TARGET_CERT"
if command -v systemctl >/dev/null 2>&1; then
    sudo systemctl reload sshd 2>/dev/null || sudo systemctl reload ssh 2>/dev/null || true
elif command -v rc-service >/dev/null 2>&1; then
    sudo rc-service sshd reload 2>/dev/null || sudo rc-service sshd restart 2>/dev/null || true
fi
echo "Host cert installed and sshd reloaded."
"@
    $ir = Invoke-RemoteSh -SshTarget $TARGET -Script $installScript -AcceptNew
    Write-Host $ir.Output
    if ($ir.ExitCode -ne 0) { Die "Failed to install host cert on ${REMOTE_HOST}." }
    Info "Host cert renewed on ${REMOTE_HOST}."
}

# ── Alias subcommand ──────────────────────────────────────────────────────────

function Invoke-Alias {
    Info "Registering alias '$REMOTE_HOST' for host via sshadmin..."

    $kr = Invoke-RemoteSh -SshTarget $TARGET -Script @'
cat /etc/ssh/ssh_host_sshadmin_ecdsa_key.pub 2>/dev/null || echo ''
hostname -f 2>/dev/null || hostname
'@ -AcceptNew
    $lines   = $kr.Output -split "`n"
    $hostKey = $lines[0].Trim()
    $fqdn    = if ($lines.Count -gt 1) { $lines[1].Trim() } else { $REMOTE_HOST }
    if (-not $hostKey) { Die "No sshadmin host key on ${REMOTE_HOST}. Run '.\sshadmin.ps1 $TARGET' first." }

    $payload = ConvertTo-B64(("{""hostname"":""{0}"",""host_key"":""{1}"",""alias"":""{2}"",""valid_days"":{3}}" `
        -f $fqdn, $hostKey.Replace('"','\"'), $REMOTE_HOST, $VALID_DAYS))
    $sr = Invoke-SshadminCmd "add_alias $payload"
    if ($sr.ExitCode -ne 0) {
        $err = Get-JsonField $sr.Output 'error'
        Die $(if ($err) { "sshadmin rejected: $err" } else { "sshadmin failed: $($sr.Output)" })
    }

    $ok = Get-JsonField $sr.Output 'ok'
    if ($ok -ne 'True') { Die "sshadmin returned error: $(Get-JsonField $sr.Output 'error')" }

    $hostCert = Get-JsonField $sr.Output 'host_cert'
    $aliases  = Get-JsonField $sr.Output 'aliases'
    if (-not $hostCert) { Die "sshadmin returned no host_cert: $($sr.Output)" }
    Info "Alias registered. Stored aliases: $(if ($aliases) { $aliases } else { $REMOTE_HOST })"

    $certB64      = ConvertTo-B64 $hostCert
    $installScript = @"
HOST_CERT=`$(printf '%s' '$certB64' | base64 -d)
TARGET_CERT=/etc/ssh/ssh_host_sshadmin_ecdsa_key-cert.pub
_have_priv=0
if [ "`$(id -u)" = "0" ]; then _have_priv=1; _priv() { "`$@"; }
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then _have_priv=1; _priv() { sudo "`$@"; }
fi
if [ "`$_have_priv" = "1" ]; then
    printf '%s\n' "`$HOST_CERT" | _priv tee "`$TARGET_CERT" > /dev/null
    _priv chmod 644 "`$TARGET_CERT"
    if command -v systemctl >/dev/null 2>&1 && _priv systemctl is-active --quiet sshd 2>/dev/null; then
        _priv systemctl reload sshd 2>/dev/null || true
    elif command -v systemctl >/dev/null 2>&1 && _priv systemctl is-active --quiet ssh 2>/dev/null; then
        _priv systemctl reload ssh 2>/dev/null || true
    elif command -v rc-service >/dev/null 2>&1; then
        _priv rc-service sshd reload 2>/dev/null || _priv rc-service sshd restart 2>/dev/null || true
    fi
    echo "Host cert updated at `$TARGET_CERT"
else
    printf '%s\n' "`$HOST_CERT" > "`$HOME/.sshadmin_host_cert.pub"
    echo "Staged at `$HOME/.sshadmin_host_cert.pub — install as root to complete update."
fi
"@
    $ir = Invoke-RemoteSh -SshTarget $TARGET -Script $installScript -AcceptNew
    Write-Host $ir.Output
    Info "Done. Alias '$REMOTE_HOST' added for $fqdn."
}

# ── Update_cert subcommand ────────────────────────────────────────────────────

function Invoke-UpdateCert {
    Info "Updating host cert for ${REMOTE_HOST} with all registered aliases..."

    $kr = Invoke-RemoteSh -SshTarget $TARGET -Script @'
cat /etc/ssh/ssh_host_sshadmin_ecdsa_key.pub 2>/dev/null || echo ''
hostname -f 2>/dev/null || hostname
'@ -AcceptNew
    $lines   = $kr.Output -split "`n"
    $hostKey = $lines[0].Trim()
    $fqdn    = if ($lines.Count -gt 1) { $lines[1].Trim() } else { $REMOTE_HOST }
    if (-not $hostKey) { Die "No sshadmin host key on ${REMOTE_HOST}. Run '.\sshadmin.ps1 $TARGET' first." }

    # Register REMOTE_HOST as alias if it differs from FQDN
    if ($REMOTE_HOST -ne $fqdn) {
        Info "  Adding $REMOTE_HOST as alias for $fqdn..."
        $aliasPayload = ConvertTo-B64(("{""hostname"":""{0}"",""host_key"":""{1}"",""alias"":""{2}"",""valid_days"":{3}}" `
            -f $fqdn, $hostKey.Replace('"','\"'), $REMOTE_HOST, $VALID_DAYS))
        $ar = Invoke-SshadminCmd "add_alias $aliasPayload"
        if ($ar.ExitCode -eq 0) {
            $aliases = Get-JsonField $ar.Output 'aliases'
            if ($aliases) { Info "  Stored aliases: $aliases" }
        }
    }

    $payload = ConvertTo-B64(("{""hostname"":""{0}"",""host_key"":""{1}"",""valid_days"":{2}}" `
        -f $fqdn, $hostKey.Replace('"','\"'), $VALID_DAYS))
    $sr = Invoke-SshadminCmd "renew_host_cert $payload"
    if ($sr.ExitCode -ne 0) {
        $err = Get-JsonField $sr.Output 'error'
        Die $(if ($err) { "sshadmin rejected: $err" } else { "sshadmin failed: $($sr.Output)" })
    }

    $hostCert = Get-JsonField $sr.Output 'host_cert'
    if (-not $hostCert) { Die "sshadmin returned no host_cert: $($sr.Output)" }

    $certB64       = ConvertTo-B64 $hostCert
    $installScript = @"
HOST_CERT=`$(printf '%s' '$certB64' | base64 -d)
TARGET_CERT=/etc/ssh/ssh_host_sshadmin_ecdsa_key-cert.pub
_have_priv=0
if [ "`$(id -u)" = "0" ]; then _have_priv=1; _priv() { "`$@"; }
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then _have_priv=1; _priv() { sudo "`$@"; }
fi
if [ "`$_have_priv" = "1" ]; then
    printf '%s\n' "`$HOST_CERT" | _priv tee "`$TARGET_CERT" > /dev/null
    _priv chmod 644 "`$TARGET_CERT"
    if command -v systemctl >/dev/null 2>&1 && _priv systemctl is-active --quiet sshd 2>/dev/null; then
        _priv systemctl reload sshd 2>/dev/null || true
    elif command -v systemctl >/dev/null 2>&1 && _priv systemctl is-active --quiet ssh 2>/dev/null; then
        _priv systemctl reload ssh 2>/dev/null || true
    elif command -v rc-service >/dev/null 2>&1; then
        _priv rc-service sshd reload 2>/dev/null || _priv rc-service sshd restart 2>/dev/null || true
    fi
    echo "Host cert updated at `$TARGET_CERT"
else
    printf '%s\n' "`$HOST_CERT" > "`$HOME/.sshadmin_host_cert.pub"
    echo "Staged at `$HOME/.sshadmin_host_cert.pub — install as root to complete update."
fi
"@
    $ir = Invoke-RemoteSh -SshTarget $TARGET -Script $installScript -AcceptNew
    Write-Host $ir.Output
    if ($ir.ExitCode -ne 0) { Die "Failed to install cert on ${REMOTE_HOST}." }
    Info "Host cert updated on ${REMOTE_HOST}."
}

# ── Add (enroll) ──────────────────────────────────────────────────────────────

function Invoke-Add {
    Info "Enrolling ${REMOTE_HOST} (remote user: ${REMOTE_USER}, sshadmin user: ${SSHADMIN_USER})"
    Info "Collecting keys from ${REMOTE_HOST}..."

    # Remove stale known_hosts entry to prevent IDENTIFICATION CHANGED errors.
    & ssh-keygen -R $REMOTE_HOST 2>$null
    $null = $LASTEXITCODE  # ignore error if entry didn't exist

    $gatherScript = @'
set -e
HOST_KEY_FILE="/etc/ssh/ssh_host_sshadmin_ecdsa_key"
HOST_KEY=""
if [ -f "${HOST_KEY_FILE}.pub" ]; then
    ktype=$(awk '{print $1}' < "${HOST_KEY_FILE}.pub")
    [ "$ktype" = "ecdsa-sha2-nistp521" ] && HOST_KEY=$(cat "${HOST_KEY_FILE}.pub")
fi
if [ -z "$HOST_KEY" ]; then
    echo "Attempting to generate host key (needs NOPASSWD sudo)..." >&2
    if sudo -n ssh-keygen -t ecdsa -b 521 -f "$HOST_KEY_FILE" -N "" -C "" -q 2>/dev/null; then
        HOST_KEY=$(cat "${HOST_KEY_FILE}.pub")
    else
        echo "Note: sudo requires password — skipping host key generation." >&2
    fi
fi
USER_KEY=""; SSHADMIN_USER_KEY_FILE="$HOME/.ssh/id_sshadmin"
for _c in "$HOME/.ssh/id_sshadmin.pub" "$HOME/.ssh/id_sshadmin_ecdsa_521.pub" "$HOME/.ssh/id_sshadmin_ed25519.pub"; do
    [ -f "$_c" ] || continue
    _kt=$(awk '{print $1}' < "$_c")
    case "$_kt" in ecdsa-sha2-nistp521|ecdsa-sha2-nistp384|ssh-ed25519)
        USER_KEY=$(cat "$_c"); SSHADMIN_USER_KEY_FILE="${_c%.pub}"; break ;; esac
done
if [ -z "$USER_KEY" ] && [ -d "$HOME/.ssh" ]; then
    for _pub in "$HOME"/.ssh/*.pub; do
        [ -f "$_pub" ] || continue
        case "$_pub" in *-cert.pub) continue ;; esac
        _kt=$(awk '{print $1}' < "$_pub")
        case "$_kt" in ecdsa-sha2-nistp521|ecdsa-sha2-nistp384|ssh-ed25519)
            USER_KEY=$(cat "$_pub"); SSHADMIN_USER_KEY_FILE="${_pub%.pub}"; break ;; esac
    done
fi
if [ -z "$USER_KEY" ]; then
    echo "Generating sshadmin key at $HOME/.ssh/id_sshadmin..." >&2
    mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"
    ssh-keygen -t ecdsa -b 521 -f "$HOME/.ssh/id_sshadmin" -N "" -q
    USER_KEY=$(cat "$HOME/.ssh/id_sshadmin.pub")
    SSHADMIN_USER_KEY_FILE="$HOME/.ssh/id_sshadmin"
fi
FQDN=$(hostname -f 2>/dev/null || hostname)
python3 - "$HOST_KEY" "$USER_KEY" "$FQDN" "$USER" "$SSHADMIN_USER_KEY_FILE" <<'PY' 2>/dev/null || \
    printf '{"hostname":"%s","user":"%s","user_key":"%s","user_key_file":"%s"}\n' "$FQDN" "$USER" "$USER_KEY" "$SSHADMIN_USER_KEY_FILE"
import sys,json
hk,uk,fqdn,user,ukf=sys.argv[1:]
d={"hostname":fqdn,"user":user,"user_key":uk,"user_key_file":ukf}
if hk: d["host_key"]=hk
print(json.dumps(d))
PY
'@

    $gr = Invoke-RemoteSh -SshTarget $TARGET -Script $gatherScript -AcceptNew
    if ($gr.ExitCode -ne 0) { Die "Failed to collect keys from ${REMOTE_HOST}: $($gr.Output)" }

    $remoteJson    = $gr.Output.Trim()
    $userKeyFile   = Get-JsonField $remoteJson 'user_key_file'
    Info "Keys collected."

    # ── Step 2: Send to sshadmin ───────────────────────────────────────────────
    Info "Sending to sshadmin (${SSHADMIN_HOST}:${SSHADMIN_SSH_PORT} as ${SSHADMIN_USER})..."

    $payload = Build-Payload $remoteJson
    $sr = Invoke-SshadminCmd "add_machine $payload"
    if ($sr.ExitCode -ne 0) {
        $err = Get-JsonField $sr.Output 'error'
        Die $(if ($err) { "sshadmin rejected: $err" } else { "sshadmin command failed. Check credentials and that SSH server is reachable on port ${SSHADMIN_SSH_PORT}." })
    }

    $ok = Get-JsonField $sr.Output 'ok'
    if ($ok -ne 'True') { Die "sshadmin rejected: $(Get-JsonField $sr.Output 'error')" }
    Info "Enrolled. Extracting certificates..."

    $hostCert = Get-JsonField $sr.Output 'host_cert'
    $userCert = Get-JsonField $sr.Output 'user_cert'
    $caPubKey = Get-JsonField $sr.Output 'ca_pubkey'

    # ── Step 3: Install on remote ──────────────────────────────────────────────
    Info "Installing certificates and configuring sshd on ${REMOTE_HOST}..."

    $hostCertB64  = ConvertTo-B64 $hostCert
    $userCertB64  = ConvertTo-B64 $userCert
    $caPubKeyB64  = ConvertTo-B64 $caPubKey
    $userKeyFileB64 = ConvertTo-B64 $userKeyFile

    $installScript = @"
set -e
HOST_CERT=`$(printf '%s' '$hostCertB64' | base64 -d)
USER_CERT=`$(printf '%s' '$userCertB64' | base64 -d)
CA_PUBKEY=`$(printf '%s' '$caPubKeyB64' | base64 -d)
USER_KEY_FILE=`$(printf '%s' '$userKeyFileB64' | base64 -d)

echo "  Installing user certificate..."
mkdir -p "`$HOME/.ssh"; chmod 700 "`$HOME/.ssh"
CERT_FILE="`${USER_KEY_FILE}-cert.pub"
printf '%s\n' "`$USER_CERT" > "`$CERT_FILE"; chmod 644 "`$CERT_FILE"
echo "  User cert: `$CERT_FILE"

_have_priv=0
if [ "`$(id -u)" = "0" ]; then _have_priv=1; _priv() { "`$@"; }
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then _have_priv=1; _priv() { sudo "`$@"; }
fi

if [ "`$_have_priv" = "1" ]; then
    echo "  Installing CA public key..."
    printf '%s\n' "`$CA_PUBKEY" | _priv tee /etc/ssh/sshadmin_ca.pub > /dev/null
    _priv chmod 644 /etc/ssh/sshadmin_ca.pub
    echo "  Configuring sshd..."
    _priv mkdir -p /etc/ssh/sshd_config.d
    printf '%s\n' '# Managed by sshadmin' 'TrustedUserCAKeys /etc/ssh/sshadmin_ca.pub' \
        | _priv tee /etc/ssh/sshd_config.d/99-sshadmin.conf > /dev/null
    if [ -n "`$HOST_CERT" ]; then
        printf '%s\n' 'HostKey /etc/ssh/ssh_host_sshadmin_ecdsa_key' \
                      'HostCertificate /etc/ssh/ssh_host_sshadmin_ecdsa_key-cert.pub' \
            | _priv tee -a /etc/ssh/sshd_config.d/99-sshadmin.conf > /dev/null
        echo "  Installing host certificate..."
        printf '%s\n' "`$HOST_CERT" | _priv tee /etc/ssh/ssh_host_sshadmin_ecdsa_key-cert.pub > /dev/null
        _priv chmod 644 /etc/ssh/ssh_host_sshadmin_ecdsa_key-cert.pub
    fi
    echo "  Adding CA to global ssh_known_hosts..."
    _priv touch /etc/ssh/ssh_known_hosts
    grep -v "sshadmin-ca`$" /etc/ssh/ssh_known_hosts > /tmp/sshadmin_kh.tmp 2>/dev/null || true
    printf '@cert-authority * %s sshadmin-ca\n' "`$CA_PUBKEY" >> /tmp/sshadmin_kh.tmp
    _priv mv /tmp/sshadmin_kh.tmp /etc/ssh/ssh_known_hosts
    _priv chmod 644 /etc/ssh/ssh_known_hosts
    echo "  Reloading sshd..."
    if command -v systemctl >/dev/null 2>&1 && _priv systemctl is-active --quiet sshd 2>/dev/null; then
        _priv systemctl reload sshd 2>/dev/null || true
    elif command -v systemctl >/dev/null 2>&1 && _priv systemctl is-active --quiet ssh 2>/dev/null; then
        _priv systemctl reload ssh 2>/dev/null || true
    elif command -v rc-service >/dev/null 2>&1; then
        _priv rc-service sshd reload 2>/dev/null || _priv rc-service sshd restart 2>/dev/null || true
    fi
else
    echo ""
    echo "  NOTE: no root or passwordless sudo — sshd configuration skipped."
    if [ -f /etc/ssh/sshd_config.d/99-sshadmin.conf ]; then
        echo "  sshd already configured for certificate auth."
    else
        echo "  To finish host setup, run the enrollment script from the sshadmin web UI as root."
    fi
    if [ -n "`$HOST_CERT" ]; then
        _STAGED="`$HOME/.sshadmin_host_cert.pub"
        printf '%s\n' "`$HOST_CERT" > "`$_STAGED"
        echo ""; echo "  Host certificate staged at: `$_STAGED"
        echo "  Install as root: cp `$_STAGED /etc/ssh/ssh_host_sshadmin_ecdsa_key-cert.pub && rc-service sshd reload"
    fi
    echo ""
fi
echo "  Done!"
"@
    $ir = Invoke-RemoteSh -SshTarget $TARGET -Script $installScript -AcceptNew
    Write-Host $ir.Output
    if ($ir.ExitCode -ne 0) { Die "Installation step failed on ${REMOTE_HOST}." }

    # ── Step 4: Update local known_hosts and ~\.ssh\config ────────────────────
    Info "Updating local known_hosts..."

    $fqdnResult = Invoke-RemoteSh -SshTarget $TARGET -Script @'
hostname -f 2>/dev/null || hostname
'@ -AcceptNew
    $localFqdn = if ($fqdnResult.ExitCode -eq 0) { $fqdnResult.Output.Trim() } else { '' }

    # Remove raw host key entries (prevents cert-failure fallback to raw key prompt)
    & ssh-keygen -R $REMOTE_HOST 2>$null; $null = $LASTEXITCODE
    if ($localFqdn -and $localFqdn -ne $REMOTE_HOST) {
        & ssh-keygen -R $localFqdn 2>$null; $null = $LASTEXITCODE
    }

    # Update local known_hosts with CA authority line
    $sshDir   = Join-Path $env:USERPROFILE '.ssh'
    $khPath   = Join-Path $sshDir 'known_hosts'
    if (-not (Test-Path $sshDir)) { New-Item -ItemType Directory -Path $sshDir | Out-Null }
    if (-not (Test-Path $khPath)) { New-Item -ItemType File -Path $khPath | Out-Null }

    $khLines = (Get-Content $khPath -Raw -ErrorAction SilentlyContinue) ?? ''
    $khLines = ($khLines -split "`n" | Where-Object { $_ -notmatch 'sshadmin-ca$' }) -join "`n"
    $khLines += "`n@cert-authority * $caPubKey sshadmin-ca`n"
    Set-Content $khPath $khLines.Trim()

    # Update ~\.ssh\config
    $cfgPath = Join-Path $sshDir 'config'
    if (-not (Test-Path $cfgPath)) { New-Item -ItemType File -Path $cfgPath | Out-Null }

    $hostPattern  = $REMOTE_HOST
    $blockMarker  = if ($localFqdn) { $localFqdn } else { $REMOTE_HOST }
    if ($localFqdn -and $localFqdn -ne $REMOTE_HOST) {
        $hostPattern = "$localFqdn $REMOTE_HOST"
    }

    # Remove existing blocks (idempotent)
    Remove-SshConfigBlock $cfgPath $blockMarker
    if ($REMOTE_HOST -ne $blockMarker) { Remove-SshConfigBlock $cfgPath $REMOTE_HOST }

    $block = @"

# sshadmin:BEGIN $blockMarker
Host $hostPattern
    IdentityFile $userKeyFile
    StrictHostKeyChecking yes
# sshadmin:END $blockMarker
"@
    Add-Content $cfgPath $block
    & icacls $cfgPath /inheritance:r /grant:r "${env:USERNAME}:(F)" 2>$null; $null = $LASTEXITCODE

    Info "Updated ~\.ssh\config: IdentityFile $userKeyFile for $hostPattern"
    Info ""
    Info "Done: ${REMOTE_HOST} enrolled successfully."
    Info "  Host cert : /etc/ssh/ssh_host_sshadmin_ecdsa_key-cert.pub  (on ${REMOTE_HOST})"
    Info "  User cert : ${userKeyFile}-cert.pub  (on ${REMOTE_HOST})"
    Info "  CA trusted: ${REMOTE_HOST} sshd + your local known_hosts"
    Info ""
    Info "  After sshd reload: ssh ${REMOTE_USER}@${REMOTE_HOST}"
}

# ── Dispatch ──────────────────────────────────────────────────────────────────

switch ($SUBCOMMAND) {
    'update'      { Invoke-Update }
    'updatehost'  { Invoke-UpdateHost }
    'alias'       { Invoke-Alias }
    'update_cert' { Invoke-UpdateCert }
    default       { Invoke-Add }
}
