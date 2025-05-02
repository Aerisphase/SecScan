$appJsPath = "src\client\static\app.js"

# Read the file content
$content = Get-Content $appJsPath -Raw

# Fix the formatting issue with the SSRF scanner line
$content = $content -replace "updateTerminal\('Running SQLI scanner on https://example\.com/login', 'info'\);\\n\s+updateTerminal\('Running SSRF scanner on https://example\.com/fetch', 'info'\);\\n\s+// Create sample vulnerabilities", "updateTerminal('Running SQLI scanner on https://example.com/login', 'info');
            updateTerminal('Running SSRF scanner on https://example.com/fetch', 'info');
            
            // Create sample vulnerabilities"

# Write the updated content back to the file
Set-Content -Path $appJsPath -Value $content -Encoding UTF8

Write-Host "Fixed formatting in app.js"
