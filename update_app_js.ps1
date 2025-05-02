$appJsPath = "src\client\static\app.js"
$content = Get-Content $appJsPath -Raw

# 1. Add SSRF scanner to the test functionality
$content = $content -replace "updateTerminal\('Running SQLI scanner on https://example\.com/login', 'info'\);\r?\n\s+", "updateTerminal('Running SQLI scanner on https://example.com/login', 'info');\n            updateTerminal('Running SSRF scanner on https://example.com/fetch', 'info');\n            "

# 2. Update the statistics to include the SSRF vulnerability
$content = $content -replace "total_vulnerabilities: 3,", "total_vulnerabilities: 4,"
$content = $content -replace "high: 2,", "high: 3,"

# 3. Add the SSRF vulnerability to the sample vulnerabilities
$ssrfVuln = @"
                    {
                        type: 'SSRF',
                        url: 'https://example.com/fetch',
                        payload: 'http://169.254.169.254/latest/meta-data/',
                        evidence: 'Cloud instance metadata exposed',
                        severity: 'high',
                        param: 'url',
                        method: 'GET',
                        recommendations: [
                            'Implement URL validation and allowlisting',
                            'Use a URL parser to validate domain and protocol',
                            'Avoid using user input directly in HTTP requests',
                            'Implement network-level protections'
                        ],
                        prevention_score: 0.88,
                        confidence: 0.94
                    },
"@

$content = $content -replace "confidence: 0\.92\r?\n\s+}\r?\n\s+],", "confidence: 0.92`n                    }`n                    ,$ssrfVuln`n                ],"

# Write the updated content back to the file
Set-Content -Path $appJsPath -Value $content -Encoding UTF8

Write-Host "Updated app.js with SSRF scanner support"
