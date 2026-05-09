# SSH host enrollment for {{ hostname }}
# Run in an elevated (Administrator) PowerShell session on the target host.
# The token below is one-time-use and expires after {{ expires_hours }} hours.
#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$SshadminUrl  = "{{ server_url }}"
$EnrollToken  = "{{ token }}"
$HostKey      = "C:\ProgramData\ssh\ssh_host_sshadmin_ecdsa_key"
$HostPub      = "$HostKey.pub"
$CaPub        = "C:\ProgramData\ssh\sshadmin_ca.pub"
$SshdConfig   = "C:\ProgramData\ssh\sshd_config"

function Write-Step { param($msg) Write-Host "[sshadmin] $msg" -ForegroundColor Cyan }

# ── Check for OpenSSH ────────────────────────────────────────────────────────
if (-not (Get-Command ssh-keygen -ErrorAction SilentlyContinue)) {
    Write-Error "ssh-keygen not found. Install the Windows OpenSSH Client feature:`n  Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0"
}
if (-not (Test-Path "C:\ProgramData\ssh")) {
    Write-Error "OpenSSH Server not installed. Install it first:`n  Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0`n  Start-Service sshd"
}

# ── Generate host key ────────────────────────────────────────────────────────
if (Test-Path $HostPub) {
    $existingType = (Get-Content $HostPub).Split(' ')[0]
    if ($existingType -ne 'ecdsa-sha2-nistp521') {
        Write-Warning "$HostPub exists with type '$existingType'; backing it up."
        $bak = "$HostKey.bak.$(Get-Date -Format 'yyyyMMddHHmmss')"
        foreach ($f in @($HostKey, $HostPub, "$HostKey-cert.pub")) {
            if (Test-Path $f) { Move-Item $f "$f$bak" }
        }
        Write-Step "Generating new ecdsa-sha2-nistp521 host key..."
        ssh-keygen -t ecdsa -b 521 -f $HostKey -N '""' -C "host:{{ hostname }}" | Out-Null
    } else {
        Write-Step "Using existing ecdsa-sha2-nistp521 host key."
    }
} else {
    Write-Step "Generating ecdsa-sha2-nistp521 host key..."
    ssh-keygen -t ecdsa -b 521 -f $HostKey -N '""' -C "host:{{ hostname }}" | Out-Null
}

$PubKeyContent = Get-Content $HostPub -Raw

# ── Install CA public key ────────────────────────────────────────────────────
Write-Step "Fetching CA public key..."
Invoke-WebRequest -Uri "$SshadminUrl/api/ca-pubkey" -OutFile $CaPub -UseBasicParsing

# ── Configure sshd ──────────────────────────────────────────────────────────
Write-Step "Configuring sshd..."
$configLines = Get-Content $SshdConfig -ErrorAction SilentlyContinue
# Remove any existing sshadmin lines and append new ones
$cleaned = $configLines | Where-Object { $_ -notmatch '(TrustedUserCAKeys|HostCertificate).*sshadmin' }
$cleaned += "# Managed by sshadmin enrollment"
$cleaned += "TrustedUserCAKeys $CaPub"
$cleaned += "HostCertificate $HostKey-cert.pub"
Set-Content $SshdConfig $cleaned

# ── Register host with sshadmin ──────────────────────────────────────────────
Write-Step "Registering host with sshadmin..."
$body = @{
    token      = $EnrollToken
    public_key = $PubKeyContent.Trim()
}
$response = Invoke-RestMethod -Uri "$SshadminUrl/api/enroll/host" `
    -Method POST -Body $body -ContentType 'application/x-www-form-urlencoded'

# ── Install host certificate ─────────────────────────────────────────────────
if ($response.cert_data) {
    Write-Step "Installing host certificate..."
    Set-Content "$HostKey-cert.pub" $response.cert_data
    Write-Host "  Certificate installed at $HostKey-cert.pub"
} else {
    Write-Warning "No certificate returned yet. Issue one from the sshadmin web UI for {{ hostname }}, then install it at $HostKey-cert.pub"
}

# ── Restart sshd ─────────────────────────────────────────────────────────────
Write-Step "Restarting sshd..."
Restart-Service sshd

Write-Step "Enrollment complete."
