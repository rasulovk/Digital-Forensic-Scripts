function Invoke-UrlThreatScan {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet("SingleFile", "Directory")]
        [string]$ScanMode,

        [Parameter(Mandatory=$false)]
        [string]$InputPath,

        [ValidateSet("False", "TrueOnline", "TrueOffline")]
        [string]$ExportBrowsingHistory = "False",

        [string]$DatabaseSavePath = "$env:TEMP\urlhaus_database.csv",
        [string]$HeaderName = "url",
        [string]$ReportPath = "Auto",

        # --- NEW: VirusTotal options ---
        [switch]$UseVirusTotal,
        [string]$VtApiKeyEnvVar = "VT_API_KEY",   # name of the env var holding your key, NOT the key itself
        [int]$VtRequestDelaySeconds = 16,          # ~4 req/min for free-tier VT API keys
        [int]$VtMaxUrlsToCheck = 0,                # 0 = no cap; set a number to limit API usage on big histories

        [switch]$ShowDebug
    )

    # --- CONFIGURATION: SHARED HOSTS ---
    $SharedHosts = @(
        "google.com", "www.google.com", "docs.google.com", "drive.google.com", "sites.google.com",
        "github.com", "raw.githubusercontent.com", "gist.github.com",
        "dropbox.com", "dl.dropboxusercontent.com",
        "microsoft.com", "onedrive.live.com", "sharepoint.com",
        "amazonaws.com", "s3.amazonaws.com",
        "facebook.com", "twitter.com", "discord.com", "cdn.discordapp.com",
        "pastebin.com", "mediafire.com"
    )

    # --- HELPER: URL NORMALIZER ---
    function Get-NormalizedUrl ($Url) {
        if ([string]::IsNullOrWhiteSpace($Url)) { return $null }
        $Clean = $Url.Trim()
        if ($Clean -match "^https?://") { $Clean = $Clean -replace "^https?://", "" }
        if ($Clean.EndsWith("/")) { $Clean = $Clean.Substring(0, $Clean.Length - 1) }
        return $Clean
    }

    function Get-HostOnly ($Url) {
        if ([string]::IsNullOrWhiteSpace($Url)) { return $null }
        if ($Url -notmatch "^http") { $Url = "http://" + $Url }
        try { return ([System.Uri]$Url).Host.Replace("www.", "").ToLower() } catch { return $null }
    }

    # --- NEW HELPER: VirusTotal URL check ---
    # Reads the key from an environment variable at call time. The key itself
    # is never written to disk, logged, or included in any report.
    function Test-VirusTotalUrl {
        param(
            [string]$Url,
            [string]$ApiKeyEnvVar
        )

        $ApiKey = [System.Environment]::GetEnvironmentVariable($ApiKeyEnvVar)
        if ([string]::IsNullOrWhiteSpace($ApiKey)) {
            Write-Warning "VirusTotal API key not found in environment variable '$ApiKeyEnvVar'. Skipping VT checks."
            return $null
        }

        $Bytes   = [System.Text.Encoding]::UTF8.GetBytes($Url)
        $UrlId   = [System.Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
        $Headers = @{ "x-apikey" = $ApiKey }

        try {
            $Resp = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/urls/$UrlId" `
                                       -Headers $Headers -Method Get -ErrorAction Stop
            $Stats = $Resp.data.attributes.last_analysis_stats
            return [PSCustomObject]@{
                Status      = "Scanned"
                Malicious   = $Stats.malicious
                Suspicious  = $Stats.suspicious
                Harmless    = $Stats.harmless
            }
        }
        catch {
            $StatusCode = $_.Exception.Response.StatusCode.value__
            if ($StatusCode -eq 404) {
                # Not yet known to VT - submit it for future scanning, don't block on result
                try {
                    Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/urls" `
                                       -Headers $Headers -Method Post -Body @{ url = $Url } -ErrorAction Stop | Out-Null
                } catch {}
                return [PSCustomObject]@{ Status = "SubmittedForScan"; Malicious = $null; Suspicious = $null; Harmless = $null }
            }
            elseif ($StatusCode -eq 429) {
                Write-Warning "VirusTotal rate limit hit. Consider increasing -VtRequestDelaySeconds."
                return [PSCustomObject]@{ Status = "RateLimited"; Malicious = $null; Suspicious = $null; Harmless = $null }
            }
            else {
                return [PSCustomObject]@{ Status = "Error_$StatusCode"; Malicious = $null; Suspicious = $null; Harmless = $null }
            }
        }
    }

    # --- 0. PATH SETUP ---
    if ($ExportBrowsingHistory -ne "False") {
        if ([string]::IsNullOrWhiteSpace($InputPath)) {
            $InputPath = Join-Path $env:TEMP "UrlScan_Forensics_$(Get-Date -Format 'yyyyMMdd')"
            if (-not (Test-Path $InputPath)) { New-Item -ItemType Directory -Path $InputPath -Force | Out-Null }
        }
        if (-not $PSBoundParameters.ContainsKey('DatabaseSavePath')) {
            $DatabaseSavePath = Join-Path -Path $InputPath -ChildPath "urlhaus_database.csv"
        }
    }
    else {
        if ([string]::IsNullOrWhiteSpace($InputPath)) { Write-Error "InputPath required."; return }
    }
    $TargetCsvToScan = $InputPath

    # --- 1. FORENSIC COLLECTION ---
    if ($ScanMode -eq "SingleFile" -and $ExportBrowsingHistory -ne "False") {
        Write-Verbose "Forensic Collection in: $InputPath"
        $ToolPath = Join-Path -Path $InputPath -ChildPath "BrowsingHistoryView.exe"
        $OutputCsv = Join-Path -Path $InputPath -ChildPath "browsing.csv"

        if ($ExportBrowsingHistory -eq "TrueOnline" -and -not (Test-Path $ToolPath)) {
            $DlUrl = if ([Environment]::Is64BitOperatingSystem) { "https://www.nirsoft.net/utils/browsinghistoryview-x64.zip" } else { "https://www.nirsoft.net/utils/browsinghistoryview.zip" }
            $Zip = Join-Path $InputPath "bhv.zip"
            try {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                Invoke-WebRequest -Uri $DlUrl -OutFile $Zip -ErrorAction Stop
                Expand-Archive -Path $Zip -DestinationPath $InputPath -Force
                Remove-Item $Zip -ErrorAction SilentlyContinue
            } catch { Write-Error "Download failed."; return }
        }

        if (Test-Path $ToolPath) {
            Write-Host "   Running BrowsingHistoryView... (Please ensure Browsers are CLOSED)" -ForegroundColor Yellow
            $Proc = Start-Process -FilePath $ToolPath -ArgumentList "/scomma `"$OutputCsv`"" -PassThru -Wait
            if (Test-Path $OutputCsv) { $TargetCsvToScan = $OutputCsv }
        }
    }

    # --- 2. LOAD & PARSE DATABASE ---
    Write-Host "[PHASE 1] Processing Threat Database..." -ForegroundColor Cyan

    $FeedUrl = "https://urlhaus.abuse.ch/downloads/csv_online/"
    if (-not (Test-Path $DatabaseSavePath) -or ((Get-Date) - (Get-Item $DatabaseSavePath).LastWriteTime).TotalHours -gt 4) {
        try { (New-Object System.Net.WebClient).DownloadFile($FeedUrl, $DatabaseSavePath) } catch {}
    }

    $MaliciousDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $MaliciousSpecificUrls = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    if (Test-Path $DatabaseSavePath) {
        $Lines = Get-Content $DatabaseSavePath
        foreach ($Line in $Lines) {
            if ($Line.StartsWith("#") -or [string]::IsNullOrWhiteSpace($Line)) { continue }
            $Cols = $Line -split ',(?=(?:[^"]*"[^"]*")*[^"]*$)'
            if ($Cols.Count -gt 2) {
                $RawUrl = $Cols[2].Trim('"')
                $Host = Get-HostOnly -Url $RawUrl
                $NormUrl = Get-NormalizedUrl -Url $RawUrl

                if ($SharedHosts -contains $Host) {
                    [void]$MaliciousSpecificUrls.Add($NormUrl)
                }
                else {
                    if ($Host) { [void]$MaliciousDomains.Add($Host) }
                    [void]$MaliciousSpecificUrls.Add($NormUrl)
                }
            }
        }
        Write-Host "   Loaded $($MaliciousDomains.Count) malicious domains." -ForegroundColor Gray
    }

    if ($UseVirusTotal) {
        $VtKeyPresent = -not [string]::IsNullOrWhiteSpace([System.Environment]::GetEnvironmentVariable($VtApiKeyEnvVar))
        if ($VtKeyPresent) {
            Write-Host "   VirusTotal checks ENABLED (key found in env:$VtApiKeyEnvVar)." -ForegroundColor Gray
        } else {
            Write-Warning "   -UseVirusTotal was set but no key found in env:$VtApiKeyEnvVar. VT checks will be skipped."
        }
    }

    # --- 3. SCANNING (RESILIENT PARSER) ---
    Write-Host "[PHASE 2] Scanning Targets..." -ForegroundColor Cyan
    $FilesToScan = if ($ScanMode -eq "SingleFile") { @(Get-Item $TargetCsvToScan) } else { Get-ChildItem $InputPath -Filter "*.csv" -Recurse -File }
    $GlobalMatches = @()
    $TotalUrlsScanned = 0
    $VtChecksPerformed = 0

    foreach ($File in $FilesToScan) {
        $FileMatches = 0

        try {
            $ContentLines = Get-Content $File.FullName -ErrorAction Stop
        } catch {
            Write-Warning "   Could not read file: $($File.Name)"
            continue
        }

        $UrlColIndex = 0
        if ($ContentLines.Count -gt 0) {
            $Header = $ContentLines[0] -split ','
            for ($i=0; $i -lt $Header.Count; $i++) {
                if ($Header[$i] -match "URL") { $UrlColIndex = $i; break }
            }
        }

        for ($i=1; $i -lt $ContentLines.Count; $i++) {
            $RowLine = $ContentLines[$i]
            if ([string]::IsNullOrWhiteSpace($RowLine)) { continue }

            $RowCols = $RowLine -split ',(?=(?:[^"]*"[^"]*")*[^"]*$)'
            if ($RowCols.Count -le $UrlColIndex) { continue }

            $UserUrl = $RowCols[$UrlColIndex].Trim('"')
            if ([string]::IsNullOrWhiteSpace($UserUrl) -or $UserUrl.Length -lt 4) { continue }

            $TotalUrlsScanned++
            $UserHost = Get-HostOnly -Url $UserUrl
            $UserNormUrl = Get-NormalizedUrl -Url $UserUrl

            if ($ShowDebug -and $UserUrl -match "42.53.59.160") {
                Write-Host "   [DEBUG] Found target IP in file! Host extracted: $UserHost" -ForegroundColor Magenta
                if ($MaliciousDomains.Contains($UserHost)) { Write-Host "   [DEBUG] Domain IS in blacklist." -ForegroundColor Magenta }
                else { Write-Host "   [DEBUG] Domain NOT in blacklist." -ForegroundColor Magenta }
            }

            $IsMatch = $false
            $Reason = ""

            if ($UserHost -and $MaliciousDomains.Contains($UserHost)) {
                $IsMatch = $true; $Reason = "Malicious Domain ($UserHost) [URLhaus]"
            }
            elseif ($MaliciousSpecificUrls.Contains($UserNormUrl)) {
                $IsMatch = $true; $Reason = "Exact URL Match [URLhaus]"
            }

            # --- NEW: VirusTotal secondary check ---
            # Only fires if URLhaus didn't already flag it, to conserve API quota.
            $VtResult = $null
            if (-not $IsMatch -and $UseVirusTotal -and $VtKeyPresent) {
                if ($VtMaxUrlsToCheck -eq 0 -or $VtChecksPerformed -lt $VtMaxUrlsToCheck) {
                    $VtResult = Test-VirusTotalUrl -Url $UserUrl -ApiKeyEnvVar $VtApiKeyEnvVar
                    $VtChecksPerformed++
                    if ($VtResult -and $VtResult.Status -eq "Scanned" -and $VtResult.Malicious -gt 0) {
                        $IsMatch = $true
                        $Reason = "VirusTotal: $($VtResult.Malicious) engines flagged malicious"
                    }
                    Start-Sleep -Seconds $VtRequestDelaySeconds
                }
            }

            if ($IsMatch) {
                Write-Host "   [!] THREAT: $UserUrl ($Reason)" -ForegroundColor Red
                $GlobalMatches += [PSCustomObject]@{
                    Timestamp      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    SourceFile     = $File.Name
                    MaliciousURL   = $UserUrl
                    DetectionType  = $Reason
                    VT_Malicious   = $VtResult.Malicious
                    VT_Suspicious  = $VtResult.Suspicious
                }
                $FileMatches++
            }
        }
        if ($FileMatches -eq 0 -and $TotalUrlsScanned -eq 0) {
             Write-Warning "   File '$($File.Name)' was scanned but 0 URLs were found. (Is it empty or corrupt?)"
        }
    }

    Write-Host "   Total URLs Verified: $TotalUrlsScanned" -ForegroundColor Gray
    if ($UseVirusTotal -and $VtKeyPresent) {
        Write-Host "   VirusTotal API calls made: $VtChecksPerformed" -ForegroundColor Gray
    }

    # --- 4. REPORT ---
    Write-Host "--------------------------------------------------"
    if ($GlobalMatches.Count -gt 0) {
        if ($ReportPath -eq "Auto") {
             $ReportPath = if ($ExportBrowsingHistory -ne "False") { Join-Path $InputPath "Threat_Report_$(Get-Date -Format 'yyyyMMdd-HHmm').csv" } else { "$($InputPath | Split-Path -Leaf)_Report.csv" }
        }
        $GlobalMatches | Export-Csv -Path $ReportPath -NoTypeInformation
        Write-Host "THREATS DETECTED: $($GlobalMatches.Count)" -ForegroundColor Red
        return $GlobalMatches
    }
    else {
        Write-Host "No malicious URLs found." -ForegroundColor Green
        return $null
    }
}
Export-ModuleMember -Function Invoke-UrlThreatScan
