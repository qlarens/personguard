param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    [ValidateSet("win-x64")]
    [string]$Runtime = "win-x64"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$localDotnetExe = Join-Path $projectRoot ".dotnet\dotnet.exe"
$projectFile = Join-Path $projectRoot "desktop\PersonGuard.Desktop\PersonGuard.Desktop.csproj"
$outputDirectory = Join-Path $projectRoot "build"

if (Test-Path -LiteralPath $localDotnetExe) {
    $dotnetExe = $localDotnetExe
}
else {
    $dotnetCommand = Get-Command dotnet -ErrorAction SilentlyContinue
    if ($null -eq $dotnetCommand) {
        throw ".NET 10 SDK не найден. Установите его в .dotnet или добавьте dotnet в PATH."
    }
    $dotnetExe = $dotnetCommand.Source
}

$env:DOTNET_CLI_TELEMETRY_OPTOUT = "1"
$env:DOTNET_NOLOGO = "1"

New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
& $dotnetExe restore $projectFile --locked-mode --nologo
if ($LASTEXITCODE -ne 0) { throw "Проверка зафиксированных зависимостей завершилась ошибкой." }

# Publish into a fresh directory and replace the canonical executable atomically.
# Direct publishing cannot reliably overwrite a running Windows executable.
$publishDirectory = Join-Path $outputDirectory (".publish-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $publishDirectory -ErrorAction Stop | Out-Null
try {
    & $dotnetExe publish $projectFile -c $Configuration -r $Runtime --self-contained true --no-restore --nologo -p:PublishSingleFile=true -p:PublishTrimmed=false -o $publishDirectory
    if ($LASTEXITCODE -ne 0) { throw "Сборка PersonGuard завершилась ошибкой." }

    $executable = Join-Path $publishDirectory "PersonGuard.exe"
    $thumbprint = $env:PERSONGUARD_SIGNING_THUMBPRINT
    if (-not [string]::IsNullOrWhiteSpace($thumbprint)) {
        $normalizedThumbprint = $thumbprint.Replace(" ", "").ToUpperInvariant()
        $certificate = Get-ChildItem -LiteralPath "Cert:\CurrentUser\My\$normalizedThumbprint" -ErrorAction Stop
        $signature = Set-AuthenticodeSignature -LiteralPath $executable -Certificate $certificate -HashAlgorithm SHA256 -TimestampServer "http://timestamp.digicert.com"
        if ($signature.Status -ne "Valid") { throw "Authenticode-подпись не прошла проверку: $($signature.StatusMessage)" }
        Write-Host "Authenticode: Valid · $($certificate.Subject)"
    }
    else {
        Write-Warning "Сертификат не задан: создана неподписанная DEV-сборка."
    }

    $hash = (Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash.ToLowerInvariant()
    $checksumPath = "$executable.sha256"
    Set-Content -LiteralPath $checksumPath -Value "$hash  PersonGuard.exe" -Encoding ascii

    $targetExecutable = Join-Path $outputDirectory "PersonGuard.exe"
    # Move-Item: Windows PowerShell 5.1 (.NET Framework) has no File.Move overwrite overload.
    Move-Item -LiteralPath $executable -Destination $targetExecutable -Force
    Move-Item -LiteralPath $checksumPath -Destination "$targetExecutable.sha256" -Force
    [IO.File]::Copy((Join-Path $projectRoot "desktop\PersonGuard.Desktop\Assets\Fonts\Manrope\OFL.txt"),
        (Join-Path $outputDirectory "Manrope.LICENSE.txt"), $true)
    $executable = $targetExecutable

    Write-Host "Готово: $executable"
    Write-Host "SHA-256: $hash"
}
finally {
    # This fresh GUID directory was created above by this invocation. Check containment
    # before removing only its generated publication output.
    $resolvedPublish = [IO.Path]::GetFullPath($publishDirectory)
    $resolvedOutput = [IO.Path]::GetFullPath($outputDirectory).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if ($resolvedPublish.StartsWith($resolvedOutput, [StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $resolvedPublish)) {
        Remove-Item -LiteralPath $resolvedPublish -Recurse -Force
    }
}
