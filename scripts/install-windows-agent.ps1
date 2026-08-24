# ==========================================
# VOC Platform - Windows Agent Installer
# Run as Administrator in PowerShell
# ==========================================

$ErrorActionPreference = "Stop"

# Configuration
$ES_HOST = "http://192.168.184.135:9200"
$KIBANA_HOST = "http://192.168.184.135:5601"
$ES_USER = "elastic"
$ES_PASS = "elasticpass123"
$AGENT_VERSION = "8.11.0"
$AGENT_DIR = "C:\Program Files\Elastic\Agent"
$CONFIG_URL = "http://192.168.184.135:5601"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " VOC Windows Agent Installer" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[ERROR] Please run this script as Administrator!" -ForegroundColor Red
    exit 1
}

# Step 1: Download Elastic Agent
Write-Host "[1/5] Downloading Elastic Agent $AGENT_VERSION..." -ForegroundColor Yellow
$downloadUrl = "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-$AGENT_VERSION-windows-x86_64.zip"
$zipPath = "$env:TEMP\elastic-agent-$AGENT_VERSION-windows-x86_64.zip"
$extractPath = "$env:TEMP\elastic-agent-extract"

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -UseBasicParsing
    Write-Host "  Downloaded OK" -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] Download failed: $_" -ForegroundColor Red
    Write-Host "  Download manually from: $downloadUrl" -ForegroundColor Yellow
    Write-Host "  Place the zip in: $zipPath" -ForegroundColor Yellow
    Read-Host "Press Enter after placing the file"
}

# Step 2: Extract
Write-Host "[2/5] Extracting..." -ForegroundColor Yellow
if (Test-Path $extractPath) { Remove-Item $extractPath -Recurse -Force }
Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
$agentFolder = Get-ChildItem $extractPath -Directory | Where-Object { $_.Name -like "elastic-agent-*" } | Select-Object -First 1
if (-not $agentFolder) {
    Write-Host "  [ERROR] Could not find elastic-agent folder in archive" -ForegroundColor Red
    exit 1
}

# Step 3: Stop existing agent if running
Write-Host "[3/5] Checking for existing agent..." -ForegroundColor Yellow
$existingService = Get-Service -Name "elastic-agent" -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Host "  Stopping existing agent..." -ForegroundColor Yellow
    Stop-Service -Name "elastic-agent" -Force -ErrorAction SilentlyContinue
    & "$AGENT_DIR\elastic-agent.exe" uninstall 2>$null
    Start-Sleep -Seconds 5
}

# Step 4: Copy to Program Files
Write-Host "[4/5] Installing to $AGENT_DIR..." -ForegroundColor Yellow
if (Test-Path $AGENT_DIR) { Remove-Item $AGENT_DIR -Recurse -Force }
Copy-Item $agentFolder.FullName -Destination $AGENT_DIR -Recurse

# Step 5: Write config
Write-Host "[5/5] Writing configuration..." -ForegroundColor Yellow
$configContent = @"
agent:
  id: "voc-windows-host"
  name: "$env:COMPUTERNAME"
  labels:
    platform: voc
    environment: production
    os: windows

outputs:
  default:
    type: elasticsearch
    hosts:
      - "$ES_HOST"
    username: "$ES_USER"
    password: "$ES_PASS"
    ssl.verification_mode: none

inputs:
  - type: winlog
    id: windows-event-logs
    name: Windows Event Logs
    enabled: true
    streams:
      windows:
        security:
          enabled: true
        system:
          enabled: true
        powershell:
          enabled: true
        powershell-script-block:
          enabled: true

  - type: system/metrics
    id: windows-system-metrics
    name: Windows System Metrics
    enabled: true
    streams:
      system.cpu:
        enabled: true
        period: 30s
      system.memory:
        enabled: true
        period: 30s
      system.network:
        enabled: true
        period: 30s
      system.process:
        enabled: true
        period: 30s
      system.filesystem:
        enabled: true
        period: 30s
      system.diskio:
        enabled: true
        period: 30s
      system.uptime:
        enabled: true
        period: 60s

  - type: system/service
    id: windows-services
    name: Windows Services
    enabled: true
    streams:
      system.service:
        enabled: true
        period: 60s

  - type: windows/perfmon
    id: windows-perfmon
    name: Windows Perfmon
    enabled: true
    streams:
      windows.perfmon:
        enabled: true
        period: 30s
        perfmon.counters:
          - object: Processor
            counters:
              - name: "% Processor Time"
            instance: "_Total"
          - object: Memory
            counters:
              - name: "Available Bytes"
              - name: "% Committed Bytes In Use"
          - object: LogicalDisk
            counters:
              - name: "% Free Space"
              - name: "Free Megabytes"
            instance: "_Total"
"@

$configPath = "$AGENT_DIR\elastic-agent.yml"
Set-Content -Path $configPath -Value $configContent -Encoding UTF8
Write-Host "  Config written to $configPath" -ForegroundColor Green

# Install and start
Write-Host ""
Write-Host "Installing Elastic Agent service..." -ForegroundColor Yellow
& "$AGENT_DIR\elastic-agent.exe" install
Start-Sleep -Seconds 3

Write-Host "Starting Elastic Agent service..." -ForegroundColor Yellow
Start-Service -Name "elastic-agent" -ErrorAction SilentlyContinue

# Cleanup
Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
Remove-Item $extractPath -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host " Installation Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Agent is now sending data to:" -ForegroundColor Cyan
Write-Host "  Elasticsearch: $ES_HOST" -ForegroundColor White
Write-Host "  Kibana: $KIBANA_HOST" -ForegroundColor White
Write-Host ""
Write-Host "View data in Kibana:" -ForegroundColor Cyan
Write-Host "  1. Go to $KIBANA_HOST" -ForegroundColor White
Write-Host "  2. Login: elastic / $ES_PASS" -ForegroundColor White
Write-Host "  3. Go to Discover" -ForegroundColor White
Write-Host "  4. Select data view: winlogbeat-*" -ForegroundColor White
Write-Host ""
Write-Host "Useful commands:" -ForegroundColor Cyan
Write-Host "  Check status:  Get-Service elastic-agent" -ForegroundColor White
Write-Host "  View logs:     Get-Content '$AGENT_DIR\data\logs\elastic-agent.log' -Tail 50" -ForegroundColor White
Write-Host "  Restart:       Restart-Service elastic-agent" -ForegroundColor White
Write-Host "  Stop:          Stop-Service elastic-agent" -ForegroundColor White
Write-Host "  Uninstall:     & '$AGENT_DIR\elastic-agent.exe' uninstall" -ForegroundColor White
