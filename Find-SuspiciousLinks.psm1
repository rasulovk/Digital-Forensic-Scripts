<#
.SYNOPSIS
    Heuristic suspicious-link analyzer for a Chrome history CSV export.

.DESCRIPTION
    Analyzes a Chrome history CSV (url, title, last_visit, visit_count) for signs of
    phishing/malicious links:
      - URL shorteners detected by pattern/shape (not a fixed list)
      - Redirect-chain correlation: if a shortener is visited and another URL follows
        within 60 seconds, the two are linked as a probable redirect chain
      - Brand impersonation: title mentions a known brand or sign-in phrase, but the
        domain does not match that brand's legitimate domain(s)
      - Other structural red flags: raw IP host, excessive hyphens, risky TLDs,
        punycode/IDN, deep subdomain nesting, long hostnames, '@' obfuscation,
        suspicious keyword + digit patterns

    Ships with sensible default brand/keyword lists; optionally override with your own
    JSON file via -BrandListPath.

.PARAMETER InputCsv
    Path to the Chrome history CSV export. Required. Must contain a 'url' column.

.PARAMETER OutputCsv
    Path for the flagged-results CSV report. Default: .\suspicious_links_report.csv

.PARAMETER BrandListPath
    Optional path to a JSON file overriding the default brand/keyword lists.
    Expected JSON shape:
    {
      "Brands": [ { "Name": "Microsoft", "Domains": ["microsoft.com","live.com","office.com","outlook.com"] }, ... ],
      "SuspiciousTitleKeywords": [ "sign in", "verify your account", "secure your account", ... ]
    }

.PARAMETER RedirectWindowSeconds
    Time window (seconds) after a shortener visit to look for a likely redirect target. Default: 60.

.EXAMPLE
    Import-Module .\Find-SuspiciousLinks.psm1
    Find-SuspiciousLinks -InputCsv .\chrome_history.csv
#>
function Find-SuspiciousLinks {

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$InputCsv,

    [string]$OutputCsv = ".\suspicious_links_report.csv",

    [string]$BrandListPath,

    [int]$RedirectWindowSeconds = 60
)

# =========================================================================
# DEFAULT BRAND / KEYWORD LISTS (used unless -BrandListPath overrides them)
# =========================================================================
$DefaultBrands = @(
    @{ Name = "Microsoft"; Domains = @("microsoft.com","live.com","office.com","outlook.com","office365.com","msn.com","microsoftonline.com","azure.com") }
    @{ Name = "Google";    Domains = @("google.com","gmail.com","accounts.google.com","youtube.com","googlemail.com") }
    @{ Name = "Apple";     Domains = @("apple.com","icloud.com","appleid.apple.com") }
    @{ Name = "PayPal";    Domains = @("paypal.com","paypal.me") }
    @{ Name = "Amazon";    Domains = @("amazon.com","amazon.co.uk","amazon.de","amazon.ca","aws.amazon.com") }
    @{ Name = "Facebook";  Domains = @("facebook.com","fb.com","messenger.com") }
    @{ Name = "Instagram"; Domains = @("instagram.com") }
    @{ Name = "Netflix";   Domains = @("netflix.com") }
    @{ Name = "Bank of America"; Domains = @("bankofamerica.com") }
    @{ Name = "Chase";     Domains = @("chase.com") }
    @{ Name = "Wells Fargo"; Domains = @("wellsfargo.com") }
    @{ Name = "Coinbase";  Domains = @("coinbase.com") }
    @{ Name = "Binance";   Domains = @("binance.com") }
    @{ Name = "LinkedIn";  Domains = @("linkedin.com") }
    @{ Name = "DHL";       Domains = @("dhl.com") }
    @{ Name = "FedEx";     Domains = @("fedex.com") }
    @{ Name = "USPS";      Domains = @("usps.com") }
)

$DefaultSuspiciousTitleKeywords = @(
    "sign in","log in","login","verify your account","verify account",
    "secure your account","account suspended","account locked","confirm your identity",
    "update your payment","unusual activity","password expired","reset your password",
    "your account has been","action required","urgent action"
)

# =========================================================================
# LOAD OVERRIDES IF PROVIDED
# =========================================================================
$Brands = $DefaultBrands
$SuspiciousTitleKeywords = $DefaultSuspiciousTitleKeywords

if ($BrandListPath) {
    if (-not (Test-Path $BrandListPath)) {
        Write-Warning "BrandListPath '$BrandListPath' not found. Using built-in defaults."
    } else {
        try {
            $Custom = Get-Content $BrandListPath -Raw | ConvertFrom-Json
            if ($Custom.Brands) { $Brands = $Custom.Brands }
            if ($Custom.SuspiciousTitleKeywords) { $SuspiciousTitleKeywords = $Custom.SuspiciousTitleKeywords }
            Write-Host "[*] Loaded custom brand/keyword list from $BrandListPath" -ForegroundColor Cyan
        } catch {
            Write-Warning "Failed to parse BrandListPath JSON. Using built-in defaults. Error: $_"
        }
    }
}

# Flat list of all known-good brand domains, built AFTER overrides are applied,
# used to (a) exclude shortener false-positives and (b) suppress generic
# sign-in flags when the domain is already a recognized trusted domain.
$AllBrandDomains = $Brands | ForEach-Object { $_.Domains } | Select-Object -Unique

# =========================================================================
# RISKY TLDs / GENERIC SUSPICIOUS KEYWORDS (path/query heuristic)
# =========================================================================
$RiskyTlds = @(
    "tk","ml","ga","cf","gq","xyz","top","club","work","click","loan",
    "win","bid","racing","review","party","gdn","men","date","stream",
    "download","icu","cam","rest","cyou","sbs"
)

$PathSuspiciousKeywords = @(
    "login","verify","secure","account","update","confirm","signin",
    "password","billing","invoice","suspended","unlock","reset","wallet"
)

# =========================================================================
# HELPER FUNCTIONS
# =========================================================================
function Get-HostOnly {
    param([string]$Url)
    if ([string]::IsNullOrWhiteSpace($Url)) { return $null }
    $u = $Url
    if ($u -notmatch "^[a-zA-Z][a-zA-Z0-9+\.\-]*://") { $u = "http://" + $u }
    try {
        $h = ([System.Uri]$u).Host.ToLower()
        # Normalize away a leading www. so "domain.com" and "www.domain.com"
        # are always treated as the same host for every comparison downstream.
        $h = $h -replace '^www\.', ''
        return $h
    } catch { return $null }
}

function Get-RegistrableDomain {
    param([string]$HostName)
    if ([string]::IsNullOrWhiteSpace($HostName)) { return $null }
    $parts = $HostName.Split('.')
    if ($parts.Count -lt 2) { return $HostName }
    return ($parts[-2] + "." + $parts[-1])
}

function Get-Tld {
    param([string]$HostName)
    if ([string]::IsNullOrWhiteSpace($HostName)) { return $null }
    $parts = $HostName.Split('.')
    if ($parts.Count -lt 2) { return $null }
    return $parts[-1].ToLower()
}

function Test-IsIpHost {
    param([string]$HostName)
    if ([string]::IsNullOrWhiteSpace($HostName)) { return $false }
    return ($HostName -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
}

function Test-IsShortenerShape {
    param([string]$HostName, [string]$PathAndQuery, [string[]]$AllowlistedDomains)

    if (-not $HostName) { return $false }

    # HostName is already normalized (no www.) by Get-HostOnly.
    if ($AllowlistedDomains -and ($AllowlistedDomains -contains $HostName)) { return $false }

    $WellKnownNonShorteners = @(
        "google.com","bing.com","yahoo.com","duckduckgo.com",
        "chatgpt.com","openai.com","github.com","stackoverflow.com",
        "wikipedia.org","reddit.com","sharepoint.com"
    )
    if ($WellKnownNonShorteners -contains $HostName) { return $false }

    if ($HostName.Length -gt 15) { return $false }
    if (-not $PathAndQuery) { return $false }

    $Path = $PathAndQuery.TrimStart('/').Split('?')[0]
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    if ($Path -match '/') { return $false }

    # Must look like an opaque random token, not a real word/endpoint name:
    # require a mix of upper+lower+digit (shortener tokens are case-sensitive
    # base62-style), and reject common real endpoint words outright.
    $CommonRealPaths = @("search","aclk","url","login","signin","auth","authorize","oauth2","home","index","about","contact","help","api","static","assets")
    if ($CommonRealPaths -contains $Path.ToLower()) { return $false }

    $HasUpper = $Path -cmatch '[A-Z]'
    $HasLower = $Path -cmatch '[a-z]'
    $HasDigit = $Path -cmatch '[0-9]'
    $MixCount = @($HasUpper,$HasLower,$HasDigit | Where-Object { $_ }).Count

    # Require at least 2 of 3 character classes present - real words are
    # almost always all-lowercase; shortener tokens mix case and digits.
    return ($Path -match '^[A-Za-z0-9_-]{4,12}$') -and ($MixCount -ge 2)
}

function Get-PathAndQuery {
    param([string]$Url)
    try {
        $u = if ($Url -match '^[a-zA-Z][a-zA-Z0-9+\.\-]*://') { $Url } else { "http://$Url" }
        return ([System.Uri]$u).PathAndQuery
    } catch { return "" }
}

# =========================================================================
# LOAD INPUT
# =========================================================================
if (-not (Test-Path $InputCsv)) {
    Write-Error "Input file not found: $InputCsv"
    return
}

Write-Host "[*] Loading: $InputCsv" -ForegroundColor Cyan
$RawRows = Import-Csv -Path $InputCsv

if (-not ($RawRows | Get-Member -Name url -ErrorAction SilentlyContinue)) {
    Write-Error "Input CSV has no 'url' column. Found columns: $($RawRows[0].PSObject.Properties.Name -join ', ')"
    return
}

$HasTitle      = [bool]($RawRows | Get-Member -Name title -ErrorAction SilentlyContinue)
$HasVisitCount = [bool]($RawRows | Get-Member -Name visit_count -ErrorAction SilentlyContinue)
$HasLastVisit  = [bool]($RawRows | Get-Member -Name last_visit -ErrorAction SilentlyContinue)

if (-not $HasLastVisit) {
    Write-Warning "No 'last_visit' column found - redirect-chain correlation will be skipped."
}

$Rows = foreach ($r in $RawRows) {
    [datetime]$ts = [datetime]::MinValue
    $ParsedOk = $false
    if ($HasLastVisit -and $r.last_visit) {
        $ParsedOk = [datetime]::TryParse($r.last_visit, [ref]$ts)
    }
    if (-not $ParsedOk) { $ts = $null }
    [PSCustomObject]@{
        Url         = $r.url
        Title       = if ($HasTitle) { $r.title } else { "" }
        VisitCount  = if ($HasVisitCount) { $r.visit_count } else { "" }
        LastVisit   = if ($HasLastVisit) { $r.last_visit } else { "" }
        Timestamp   = $ts
    }
}
$Rows = $Rows | Sort-Object Timestamp

Write-Host "[*] Loaded $($Rows.Count) rows. Analyzing..." -ForegroundColor Cyan

# =========================================================================
# MAIN ANALYSIS
# =========================================================================
$Results = New-Object System.Collections.Generic.List[PSObject]
$SeenUrls = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

for ($i = 0; $i -lt $Rows.Count; $i++) {
    $Row = $Rows[$i]
    $Url = $Row.Url
    if ([string]::IsNullOrWhiteSpace($Url)) { continue }
    if (-not $SeenUrls.Add($Url)) { continue }

    $HostName = Get-HostOnly -Url $Url
    if (-not $HostName) { continue }

    $Tld = Get-Tld -HostName $HostName
    $RegDomain = Get-RegistrableDomain -HostName $HostName
    $PathAndQuery = Get-PathAndQuery -Url $Url
    $TitleLower = if ($Row.Title) { $Row.Title.ToLower() } else { "" }

    $Reasons = New-Object System.Collections.Generic.List[string]
    $Score = 0
    $PossibleRedirectTo = ""

    $IsShortener = Test-IsShortenerShape -HostName $HostName -PathAndQuery $PathAndQuery -AllowlistedDomains $AllBrandDomains
    if ($IsShortener) {
        $Reasons.Add("URL shape matches a shortener pattern (short host + short opaque path)")
        $Score += 30

        if ($Row.Timestamp) {
            for ($j = $i + 1; $j -lt $Rows.Count; $j++) {
                $Next = $Rows[$j]
                if (-not $Next.Timestamp) { continue }
                $Delta = ($Next.Timestamp - $Row.Timestamp).TotalSeconds
                if ($Delta -lt 0) { continue }
                if ($Delta -gt $RedirectWindowSeconds) { break }
                if ($Next.Url -eq $Url) { continue }
                $PossibleRedirectTo = $Next.Url
                $Reasons.Add("Shortener followed by '$($Next.Url)' within $([math]::Round($Delta,1))s - possible redirect")
                $Score += 15
                break
            }
        }
    }

    $MentionedBrand = $null
    foreach ($Brand in $Brands) {
        if ($TitleLower -match [regex]::Escape($Brand.Name.ToLower())) {
            $MentionedBrand = $Brand
            break
        }
    }
    $MentionsSignInPhrase = $false
    foreach ($Kw in $SuspiciousTitleKeywords) {
        if ($TitleLower -match [regex]::Escape($Kw.ToLower())) { $MentionsSignInPhrase = $true; break }
    }

    if ($MentionedBrand) {
        $DomainMatches = $MentionedBrand.Domains | Where-Object { $RegDomain -eq $_ -or $HostName -eq $_ -or $HostName.EndsWith(".$_") }
        if (-not $DomainMatches) {
            $Reasons.Add("Title mentions '$($MentionedBrand.Name)' but domain '$HostName' does not match $($MentionedBrand.Name)'s known domains - possible impersonation")
            $Score += 50
        }
    }
    elseif ($MentionsSignInPhrase) {
        $DomainIsTrusted = $AllBrandDomains | Where-Object { $RegDomain -eq $_ -or $HostName -eq $_ -or $HostName.EndsWith(".$_") }
        if (-not $DomainIsTrusted) {
            $Reasons.Add("Title contains a sign-in/account phrase with no recognized brand - verify domain manually")
            $Score += 15
        }
    }

    if (Test-IsIpHost -HostName $HostName) {
        $Reasons.Add("Raw IP address used as host")
        $Score += 35
    }

    $HyphenCount = ($HostName.ToCharArray() | Where-Object { $_ -eq '-' }).Count
    if ($HyphenCount -ge 3) {
        $Reasons.Add("Excessive hyphens in domain ($HyphenCount)")
        $Score += 15
    }

    if ($Tld -and ($RiskyTlds -contains $Tld)) {
        $Reasons.Add("High-risk/low-cost TLD (.$Tld)")
        $Score += 20
    }

    if ($HostName -match 'xn--') {
        $Reasons.Add("Punycode/IDN host (possible homograph attack)")
        $Score += 25
    }

    $LabelCount = $HostName.Split('.').Count
    if ($LabelCount -ge 5) {
        $Reasons.Add("Unusually deep subdomain nesting ($LabelCount levels)")
        $Score += 15
    }

    if ($HostName.Length -ge 40) {
        $Reasons.Add("Unusually long hostname ($($HostName.Length) chars)")
        $Score += 10
    }

    if ($Url -match '@') {
        $Reasons.Add("'@' symbol present (possible redirect obfuscation)")
        $Score += 25
    }

    $PathLower = $PathAndQuery.ToLower()
    $MatchedPathKeywords = $PathSuspiciousKeywords | Where-Object { $PathLower -like "*$_*" }
    if ($MatchedPathKeywords.Count -gt 0 -and $PathLower -match '\d{2,}') {
        $Reasons.Add("Suspicious keyword(s) [$($MatchedPathKeywords -join ', ')] combined with numeric pattern in path/query")
        $Score += 20
    }
    elseif ($MatchedPathKeywords.Count -ge 2) {
        $Reasons.Add("Multiple suspicious keywords in path/query [$($MatchedPathKeywords -join ', ')]")
        $Score += 10
    }

    if ($Reasons.Count -eq 0) { continue }

    $RiskLevel = if ($Score -ge 50) { "High" } elseif ($Score -ge 25) { "Medium" } else { "Low" }

    $Results.Add([PSCustomObject][ordered]@{
        Url                  = $Url
        Title                = $Row.Title
        DateAccessed         = $Row.LastVisit
        VisitCount           = $Row.VisitCount
        RiskScore            = $Score
        RiskLevel            = $RiskLevel
        Reasons              = ($Reasons -join " | ")
        PossibleRedirectTo   = $PossibleRedirectTo
    })
}

# =========================================================================
# OUTPUT
# =========================================================================
$Sorted = $Results | Sort-Object -Property RiskScore -Descending

Write-Host ""
Write-Host "=================================================================" -ForegroundColor DarkGray
Write-Host "  SUSPICIOUS LINK SCAN RESULTS" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor DarkGray

if ($Sorted.Count -eq 0) {
    Write-Host "No suspicious patterns detected." -ForegroundColor Green
}
else {
    foreach ($R in $Sorted) {
        $Color = switch ($R.RiskLevel) {
            "High"   { "Red" }
            "Medium" { "Yellow" }
            default  { "DarkYellow" }
        }
        Write-Host ("[{0,-6}] Score:{1,3}  {2}" -f $R.RiskLevel, $R.RiskScore, $R.Url) -ForegroundColor $Color
        Write-Host ("           Title:    $($R.Title)") -ForegroundColor DarkGray
        Write-Host ("           Accessed: $($R.DateAccessed)   Visits: $($R.VisitCount)") -ForegroundColor DarkGray
        Write-Host ("           Reasons:  $($R.Reasons)") -ForegroundColor Gray
        if ($R.PossibleRedirectTo) {
            Write-Host ("           -> Possible redirect to: $($R.PossibleRedirectTo)") -ForegroundColor Magenta
        }
    }

    Write-Host ""
    Write-Host ("Total flagged: {0}  (High: {1}, Medium: {2}, Low: {3})" -f `
        $Sorted.Count, `
        ($Sorted | Where-Object RiskLevel -eq "High").Count, `
        ($Sorted | Where-Object RiskLevel -eq "Medium").Count, `
        ($Sorted | Where-Object RiskLevel -eq "Low").Count) -ForegroundColor Cyan

    $Sorted | Export-Csv -Path $OutputCsv -NoTypeInformation
    Write-Host "Report saved to: $OutputCsv" -ForegroundColor Green
}

}

Export-ModuleMember -Function Find-SuspiciousLinks
