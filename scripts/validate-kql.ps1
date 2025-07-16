<#
.SYNOPSIS
    Validates KQL queries in Terraform files
.DESCRIPTION
    Parses Terraform files and validates KQL queries for syntax
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$TerraformPath
)

function Test-KQLSyntax {
    param([string]$Query)
    
    # Basic syntax validation
    $errors = @()
    
    if ($Query -notmatch '\w+\s*\|') {
        $errors += "Missing table name at start of query"
    }
    
    if (($Query -split '\|').Count -lt 2) {
        $errors += "Query must have at least one pipe operator"
    }
    
    return $errors
}

# Extract and validate queries
$files = Get-ChildItem -Path $TerraformPath -Filter "*.tf" -Recurse
$totalQueries = 0
$validQueries = 0

foreach ($file in $files) {
    $content = Get-Content -Path $file.FullName -Raw
    $pattern = '(?s)query\s*=\s*<<-EOQ\s*(.*?)\s*EOQ'
    $matches = [regex]::Matches($content, $pattern)
    
    foreach ($match in $matches) {
        $totalQueries++
        $query = $match.Groups[1].Value
        $errors = Test-KQLSyntax -Query $query
        
        if ($errors.Count -eq 0) {
            $validQueries++
            Write-Host "✅ Valid query in $($file.Name)" -ForegroundColor Green
        } else {
            Write-Host "❌ Invalid query in $($file.Name):" -ForegroundColor Red
            $errors | ForEach-Object { Write-Host "   - $_" -ForegroundColor Red }
        }
    }
}

Write-Host "`nValidation Summary:" -ForegroundColor Cyan
Write-Host "Total queries: $totalQueries"
Write-Host "Valid queries: $validQueries"
Write-Host "Invalid queries: $($totalQueries - $validQueries)"
