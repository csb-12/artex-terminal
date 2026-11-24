# 无窗启动 pos-delivery HTTP :9911。任意克隆路径都可用。
$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$script = Join-Path $repo "mcp\pos-delivery\run_http_9911.py"
if (-not (Test-Path $script)) { throw "找不到 $script" }

$pyw = Get-Command pythonw.exe -ErrorAction SilentlyContinue
if (-not $pyw) {
    $candidates = @(
        "$env:LOCALAPPDATA\Programs\Python\Python314\pythonw.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python313\pythonw.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python312\pythonw.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python311\pythonw.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python310\pythonw.exe"
    )
    $pywPath = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $pywPath) { throw "找不到 pythonw.exe，请安装 Python 3.10+ 并加入 PATH" }
} else {
    $pywPath = $pyw.Source
}

Start-Process -FilePath $pywPath -ArgumentList "`"$script`"" -WorkingDirectory (Split-Path $script) -WindowStyle Hidden
Write-Host "pos-delivery 已在后台启动。检查 http://127.0.0.1:9911/health"
