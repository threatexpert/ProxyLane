param(
    [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot)
)

$localeDirectory = Join-Path $ProjectRoot 'src\ProxyLane\locales'
$zhPath = Join-Path $localeDirectory 'zh-CN.json'
$enPath = Join-Path $localeDirectory 'en-US.json'

$zh = Get-Content -LiteralPath $zhPath -Raw -Encoding UTF8 | ConvertFrom-Json
$en = Get-Content -LiteralPath $enPath -Raw -Encoding UTF8 | ConvertFrom-Json
$zhKeys = @($zh.psobject.Properties.Name | Sort-Object)
$enKeys = @($en.psobject.Properties.Name | Sort-Object)
$difference = @(Compare-Object $zhKeys $enKeys)

if ($difference.Count -ne 0) {
    Write-Error "Locale catalogs do not contain the same keys:`n$($difference | Out-String)"
    exit 1
}

$emptyValues = @()
foreach ($key in $zhKeys) {
    if ([string]::IsNullOrEmpty($zh.$key) -or [string]::IsNullOrEmpty($en.$key)) {
        $emptyValues += $key
    }
}
if ($emptyValues.Count -ne 0) {
    Write-Error "Locale values must not be empty: $($emptyValues -join ', ')"
    exit 1
}

$resourcePath = Join-Path $ProjectRoot 'src\ProxyLane\ProxyLane.rc'
$unicodeEscapes = @(Select-String -LiteralPath $resourcePath -Pattern '\\x[0-9A-Fa-f]{4}')
if ($unicodeEscapes.Count -ne 0) {
    Write-Error 'ProxyLane.rc contains Unicode escape sequences; put interface text in the locale catalogs instead.'
    exit 1
}

Write-Output "Locale catalogs are valid and contain $($zhKeys.Count) matching keys."
