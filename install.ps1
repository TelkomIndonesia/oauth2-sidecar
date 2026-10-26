# Usage: irm https://raw.githubusercontent.com/TelkomIndonesia/oauth2-sidecar/main/install.ps1 | iex
# The script block keeps iex from changing the caller's preferences and variables.
& {
  Set-StrictMode -Version 3
  $ErrorActionPreference = 'Stop'
  $ProgressPreference = 'SilentlyContinue'
  # Old .NET Framework defaults lack TLS 1.2, which GitHub requires. Leave SystemDefault (0)
  # alone: the setting is process-wide, and OR-ing in Tls12 would pin it and drop TLS 1.3.
  $tls = [Net.ServicePointManager]::SecurityProtocol
  if ($tls -ne 0 -and -not ($tls -band [Net.SecurityProtocolType]::Tls12)) {
    [Net.ServicePointManager]::SecurityProtocol = $tls -bor [Net.SecurityProtocolType]::Tls12
  }

  $repo = 'TelkomIndonesia/oauth2-sidecar'
  $version = $env:OAUTH2_SIDECAR_VERSION
  if (-not $version) {
    $version = (Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest").tag_name
  }
  if (-not $version) { throw 'could not determine release version' }
  if (-not $version.StartsWith('v')) { $version = "v$version" }

  # A 32-bit shell on 64-bit Windows reports the real CPU in PROCESSOR_ARCHITEW6432.
  $cpu = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
  $arch = switch ($cpu) {
    'AMD64' { 'amd64' }
    'ARM64' { 'arm64' }
    default { throw "unsupported architecture: $cpu" }
  }

  $asset = "oauth2-sidecar_$($version.Substring(1))_windows_$arch.zip"
  $base = "https://github.com/$repo/releases/download/$version"
  $tmp = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
  New-Item -ItemType Directory -Path $tmp | Out-Null
  try {
    Invoke-WebRequest "$base/$asset" -OutFile "$tmp\$asset" -UseBasicParsing
    Invoke-WebRequest "$base/checksums.txt" -OutFile "$tmp\checksums.txt" -UseBasicParsing
    $line = Get-Content "$tmp\checksums.txt" | Where-Object { $_.EndsWith("  $asset") } | Select-Object -First 1
    if (-not $line) { throw "no checksum for $asset" }
    if ((Get-FileHash "$tmp\$asset" -Algorithm SHA256).Hash -ne $line.Split(' ')[0]) { throw "checksum mismatch for $asset" }
    Write-Host "${asset}: OK"

    $target = if ($env:INSTALL_DIR) {
      $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($env:INSTALL_DIR)
    } else {
      Join-Path $env:LOCALAPPDATA 'Programs\oauth2-sidecar'
    }
    Expand-Archive "$tmp\$asset" -DestinationPath "$tmp\x"
    New-Item -ItemType Directory -Path $target -Force | Out-Null
    Copy-Item "$tmp\x\oauth2-sidecar.exe" $target -Force
    Write-Host "installed oauth2-sidecar $version to $target\oauth2-sidecar.exe"
  } finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
  }

  # Edit the registry value directly: [Environment]::SetEnvironmentVariable would turn
  # a REG_EXPAND_SZ Path into REG_SZ and break entries such as %USERPROFILE%\bin.
  $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
  try {
    $path = [string]$key.GetValue('Path', '', 'DoNotExpandEnvironmentNames')
    if (($path -split ';') -notcontains $target) {
      $kind = if ($key.GetValueNames() -contains 'Path') { $key.GetValueKind('Path') } else { 'ExpandString' }
      $new = if ($path) { $path.TrimEnd(';') + ';' + $target } else { $target }
      $key.SetValue('Path', $new, $kind)
      # Setting any user variable broadcasts WM_SETTINGCHANGE, so new terminals see the new Path.
      [Environment]::SetEnvironmentVariable('OAUTH2_SIDECAR_INSTALL', '1', 'User')
      [Environment]::SetEnvironmentVariable('OAUTH2_SIDECAR_INSTALL', $null, 'User')
      Write-Host "added $target to the user Path; open a new terminal to use it"
    }
  } finally {
    $key.Close()
  }
  if (($env:Path -split ';') -notcontains $target) { $env:Path = "$env:Path;$target" }
}
