# start_servers.ps1 — Launch both demo RAG servers in separate background jobs
$root = Split-Path -Parent $PSScriptRoot
$venv = Join-Path $root ".venv\Scripts\uvicorn"

Write-Host "Starting VulnerableRAGBot on port 8001..."
$job1 = Start-Job -ScriptBlock {
    param($venv, $root)
    Set-Location $root
    & $venv demo.vulnerable_rag:app --host 127.0.0.1 --port 8001
} -ArgumentList $venv, $root

Write-Host "Starting ProtectedRAGBot on port 8002..."
$job2 = Start-Job -ScriptBlock {
    param($venv, $root)
    Set-Location $root
    & $venv demo.protected_rag:app --host 127.0.0.1 --port 8002
} -ArgumentList $venv, $root

Write-Host "Waiting for servers to start..."
Start-Sleep -Seconds 3

Write-Host "Running demo..."
& (Join-Path $root ".venv\Scripts\python") (Join-Path $root "demo\run_demo.py")
