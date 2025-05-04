document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const scanFormElement = document.getElementById('scanForm');
    const resultsCard = document.getElementById('resultsCard');
    const scanStats = document.getElementById('scanStats');
    const vulnerabilities = document.getElementById('vulnerabilities');
    const exportResultsBtn = document.getElementById('exportResults');
    const clearResultsBtn = document.getElementById('clearResults');
    const randomizeUserAgentBtn = document.getElementById('randomizeUserAgent');
    const testButton = document.getElementById('testButton');
    const terminalContent = document.getElementById('terminalContent');
    const jsEnabledCheckbox = document.getElementById('jsEnabled');
    const jsOptionsDiv = document.querySelector('.js-options');
    const wafOptionsDiv = document.querySelector('.waf-options');
    const terminalStatus = document.querySelector('.terminal-status');

    // API configuration
    const API_HOST = window.location.hostname;
    const API_PORT = window.location.port || '8001';
    const API_URL = `https://${API_HOST}:${API_PORT}`;
    const WS_URL = `wss://${API_HOST}:${API_PORT}/ws/logs`;

    // Get API key from localStorage or prompt user
    let API_KEY = localStorage.getItem('secscan_api_key');
    if (!API_KEY) {
        API_KEY = prompt('Please enter your API key (set SECSCAN_API_KEY environment variable on server):');
        if (API_KEY) {
            localStorage.setItem('secscan_api_key', API_KEY);
        } else {
            alert('API key is required to use SecScan. Please refresh the page and enter your API key.');
            return;
        }
    }

    // Handle API errors
    function handleApiError(error) {
        console.error('API Error:', error);
        let errorMessage = 'An error occurred while communicating with the server.';
        
        if (error.message.includes('Failed to fetch')) {
            errorMessage = 'Could not connect to the server. Please make sure the server is running and SSL certificates are valid.';
        } else if (error.message.includes('401') || error.message.includes('403')) {
            errorMessage = 'Invalid API key. Please make sure you have set the SECSCAN_API_KEY environment variable on the server and entered the correct key.';
            localStorage.removeItem('secscan_api_key');
        } else if (error.message.includes('SSL')) {
            errorMessage = 'SSL certificate error. Please ensure you trust the server\'s certificate.';
        } else if (error.message.includes('NetworkError')) {
            errorMessage = 'Network error. Please check your internet connection and try again.';
        } else if (error.message.includes('CORS')) {
            errorMessage = 'CORS error. Please ensure the server is configured to accept requests from this origin.';
        }
        
        scanStats.innerHTML = `<div class="alert alert-danger">
            <i class="bi bi-exclamation-triangle me-2"></i>${errorMessage}
        </div>`;
    }

    // Validate User-Agent
    function validateUserAgent(userAgent) {
        if (!userAgent) {
            return true;
        }
        
        const regex = /^[a-zA-Z0-9\s\(\)\.\/\-\:\;\,\+\=\_]+$/;
        if (!regex.test(userAgent)) {
            alert('Invalid User-Agent format. Please use only alphanumeric characters and common symbols.');
            return false;
        }
        
        return true;
    }

    // Randomize User-Agent
    function randomizeUserAgent() {
        const userAgents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        ];
        document.getElementById('userAgent').value = userAgents[Math.floor(Math.random() * userAgents.length)];
    }

    // Export results
    function exportResults() {
        // Get the scan data from the UI
        const scanDate = new Date().toLocaleString();
        const targetUrl = document.getElementById('targetUrl')?.value || 'Unknown Target';
        
        // Create a structured report object
        const reportData = {
            scanInfo: {
                date: scanDate,
                target: targetUrl,
                scannerVersion: '1.0.0'
            },
            summary: {}
        };
        
        // Extract statistics
        const statCards = document.querySelectorAll('.stat-card-value');
        if (statCards.length >= 4) {
            reportData.summary = {
                pagesCrawled: statCards[0]?.textContent || '0',
                linksFound: statCards[1]?.textContent || '0',
                formsFound: statCards[2]?.textContent || '0',
                jsEnabled: statCards[3]?.textContent || 'Disabled'
            };
        }
        
        // Extract vulnerability data
        reportData.vulnerabilities = [];
        
        // Process each vulnerability group
        const vulnGroups = document.querySelectorAll('.vulnerability-group');
        vulnGroups.forEach(group => {
            const groupType = group.querySelector('.vulnerability-group-header h6')?.textContent.trim() || 'Unknown';
            const groupSeverity = group.className.includes('critical') ? 'critical' : 
                                 group.className.includes('high') ? 'high' : 
                                 group.className.includes('medium') ? 'medium' : 'low';
            
            // Get individual vulnerabilities in this group
            const vulnItems = group.querySelectorAll('.vulnerability-item');
            vulnItems.forEach(item => {
                const vulnTitle = item.querySelector('h6')?.textContent.trim() || 'Unknown Vulnerability';
                const vulnDetails = item.querySelectorAll('.vulnerability-details p');
                const vulnSeverity = item.className.includes('critical') ? 'critical' : 
                                    item.className.includes('high') ? 'high' : 
                                    item.className.includes('medium') ? 'medium' : 'low';
                
                // Extract parameter, payload, and evidence
                let parameter = '', payload = '', evidence = '', confidence = '', prevention = '';
                vulnDetails.forEach(detail => {
                    const text = detail.textContent;
                    if (text.includes('Parameter:')) parameter = text.split('Parameter:')[1].trim();
                    if (text.includes('Payload:')) payload = text.split('Payload:')[1].trim();
                    if (text.includes('Evidence:')) evidence = text.split('Evidence:')[1].trim();
                    if (text.includes('Confidence')) confidence = text.match(/Confidence (\d+)%/) ? text.match(/Confidence (\d+)%/)[1] + '%' : '';
                    if (text.includes('Prevention')) prevention = text.match(/Prevention (\d+)%/) ? text.match(/Prevention (\d+)%/)[1] + '%' : '';
                });
                
                // Extract recommendations
                const recommendations = [];
                const recItems = item.querySelectorAll('.recommendations .list-group-item');
                recItems.forEach(rec => {
                    recommendations.push(rec.textContent.trim());
                });
                
                // Add to the vulnerability list
                reportData.vulnerabilities.push({
                    type: vulnTitle.split(' at ')[0].trim(),
                    url: vulnTitle.includes(' at ') ? vulnTitle.split(' at ')[1].trim() : '',
                    severity: vulnSeverity,
                    parameter: parameter,
                    payload: payload,
                    evidence: evidence,
                    confidence: confidence,
                    prevention: prevention,
                    recommendations: recommendations
                });
            });
        });
        
        // Count vulnerabilities by severity
        const severityCounts = {
            critical: reportData.vulnerabilities.filter(v => v.severity === 'critical').length,
            high: reportData.vulnerabilities.filter(v => v.severity === 'high').length,
            medium: reportData.vulnerabilities.filter(v => v.severity === 'medium').length,
            low: reportData.vulnerabilities.filter(v => v.severity === 'low').length
        };
        reportData.summary.vulnerabilitiesBySeverity = severityCounts;
        reportData.summary.totalVulnerabilities = reportData.vulnerabilities.length;
        
        // Generate a formatted report
        const formattedReport = JSON.stringify(reportData, null, 2);
        
        // Create and download the file
        const blob = new Blob([formattedReport], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `secscan-report-${targetUrl.replace(/[^a-zA-Z0-9]/g, '-')}-${new Date().toISOString().split('T')[0]}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    // Clear results
    function clearResults() {
        scanStats.innerHTML = '';
        vulnerabilities.innerHTML = '';
        resultsCard.style.display = 'none';
    }

    // Event Listeners
    if (exportResultsBtn) {
        exportResultsBtn.addEventListener('click', exportResults);
    }
    
    if (clearResultsBtn) {
        clearResultsBtn.addEventListener('click', clearResults);
    }
    
    if (randomizeUserAgentBtn) {
        randomizeUserAgentBtn.addEventListener('click', randomizeUserAgent);
    }

    // Terminal Management
    let isTerminalPaused = false;
    let ws = null;

    function connectWebSocket() {
        if (ws) {
            ws.close();
        }

        try {
            ws = new WebSocket(WS_URL, ['v1.secscan']);
            
            ws.onopen = () => {
                updateTerminal('Connected to server', 'info');
                if (terminalStatus) {
                    terminalStatus.textContent = 'Connected';
                    terminalStatus.style.backgroundColor = '#4CAF50';
                }
            };
            
            ws.onclose = (event) => {
                updateTerminal(`Disconnected from server (${event.code})`, 'warning');
                if (terminalStatus) {
                    terminalStatus.textContent = 'Disconnected';
                    terminalStatus.style.backgroundColor = '#f44336';
                }
                
                // Try to reconnect after 5 seconds
                setTimeout(connectWebSocket, 5000);
            };
            
            ws.onerror = (error) => {
                updateTerminal(`WebSocket error: ${error.message}`, 'error');
            };
            
            ws.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    
                    // Handle ping/pong messages
                    if (data.type === 'ping') {
                        ws.send(JSON.stringify({ type: 'pong' }));
                        return;
                    }
                    if (data.type === 'pong') {
                        return;
                    }

                    // Handle regular messages
                    if (data.message) {
                        updateTerminal(data.message, 'info');
                    }
                } catch (e) {
                    updateTerminal(`Invalid message format: ${event.data}`, 'error');
                }
            };
        } catch (error) {
            updateTerminal(`Failed to create WebSocket connection: ${error.message}`, 'error');
            setTimeout(connectWebSocket, 5000);
        }
    }

    function updateTerminal(message, type = 'info') {
        if (isTerminalPaused || !terminalContent) return;
        
        const timestamp = new Date().toLocaleTimeString();
        const line = document.createElement('div');
        line.className = `terminal-line ${type}`;
        
        const timestampSpan = document.createElement('span');
        timestampSpan.className = 'terminal-timestamp';
        timestampSpan.textContent = `[${timestamp}]`;
        
        const messageSpan = document.createElement('span');
        messageSpan.className = 'terminal-message';
        
        // Format page processing messages
        if (message && typeof message === 'string') {
            if (message.includes('Processed page')) {
                const parts = message.split(' ');
                const pageNumber = parts[parts.length - 1].replace(/[()]/g, '');
                const url = parts.slice(3, -1).join(' ');
                
                messageSpan.innerHTML = `Processed page <span class="terminal-url">${url}</span> <span class="terminal-page-number">${pageNumber}</span>`;
            } else if (message.includes('Running') && message.includes('scanner')) {
                const parts = message.split(' ');
                const scannerType = parts[1];
                const url = parts.slice(3).join(' ');
                
                messageSpan.innerHTML = `Running <span class="terminal-scanner">${scannerType}</span> scanner on <span class="terminal-url">${url}</span>`;
            } else if (message.includes('Found') && message.includes('vulnerabilities')) {
                const parts = message.split(' ');
                const count = parts[1];
                const url = parts.slice(4).join(' ');
                
                messageSpan.innerHTML = `Found <span class="terminal-vuln-count">${count}</span> vulnerabilities on <span class="terminal-url">${url}</span>`;
            } else if (message.includes('Starting scan')) {
                messageSpan.innerHTML = `<span class="terminal-highlight">Starting scan...</span>`;
            } else if (message.includes('Target:')) {
                const url = message.split('Target: ')[1];
                messageSpan.innerHTML = `Target: <span class="terminal-url">${url}</span>`;
            } else if (message.includes('Selected scanners:')) {
                const scanners = message.split('Selected scanners: ')[1];
                messageSpan.innerHTML = `Selected scanners: <span class="terminal-scanners">${scanners}</span>`;
            } else if (message.includes('Scan completed')) {
                messageSpan.innerHTML = `<span class="terminal-success">Scan completed successfully</span>`;
            } else if (message.includes('Error:')) {
                messageSpan.innerHTML = `<span class="terminal-error">${message}</span>`;
            } else {
                messageSpan.textContent = message;
            }
        } else {
            messageSpan.textContent = message;
        }
        
        line.appendChild(timestampSpan);
        line.appendChild(document.createTextNode(' '));
        line.appendChild(messageSpan);
        
        terminalContent.appendChild(line);
        terminalContent.scrollTop = terminalContent.scrollHeight;
    }

    function clearTerminal() {
        if (terminalContent) {
            terminalContent.innerHTML = '';
            updateTerminal('Terminal cleared', 'info');
        }
    }

    function toggleTerminalPause() {
        isTerminalPaused = !isTerminalPaused;
        const pauseButton = document.getElementById('pauseTerminal');
        if (pauseButton) {
            pauseButton.innerHTML = isTerminalPaused ? 
                '<i class="bi bi-play-fill me-1"></i>Resume' : 
                '<i class="bi bi-pause-fill me-1"></i>Pause';
        }
        updateTerminal(`Terminal ${isTerminalPaused ? 'paused' : 'resumed'}`, 'info');
    }

    // Initialize WebSocket connection when the page loads
    connectWebSocket();
    
    // Event Listeners for terminal controls
    const clearTerminalBtn = document.getElementById('clearTerminal');
    const pauseTerminalBtn = document.getElementById('pauseTerminal');
    
    if (clearTerminalBtn) {
        clearTerminalBtn.addEventListener('click', clearTerminal);
    }
    
    if (pauseTerminalBtn) {
        pauseTerminalBtn.addEventListener('click', toggleTerminalPause);
    }
    
    // Keep WebSocket connection alive
    setInterval(() => {
        if (ws && ws.readyState === WebSocket.OPEN) {
            try {
                ws.send(JSON.stringify({ type: 'ping' }));
            } catch (error) {
                updateTerminal(`Failed to send ping: ${error.message}`, 'error');
                connectWebSocket();
            }
        }
    }, 30000);

    // Scanner Checkboxes Management
    const allScannersCheckbox = document.getElementById('allScanners');
    const scannerCheckboxes = document.querySelectorAll('.scanner-checkbox');
    
    // Function to handle the "All scanners" checkbox
    function handleAllScannersCheckbox() {
        if (!allScannersCheckbox) return;
        
        const isChecked = allScannersCheckbox.checked;
        
        // Update all scanner checkboxes
        scannerCheckboxes.forEach(checkbox => {
            checkbox.checked = isChecked;
        });
        
        updateTerminal(`${isChecked ? 'Selected' : 'Deselected'} all scanners`, 'info');
    }
    
    // Function to update the "All scanners" checkbox based on individual selections
    function updateAllScannersCheckbox() {
        if (!allScannersCheckbox) return;
        
        const allChecked = Array.from(scannerCheckboxes).every(checkbox => checkbox.checked);
        const anyChecked = Array.from(scannerCheckboxes).some(checkbox => checkbox.checked);
        
        // Update the "All scanners" checkbox without triggering its change event
        allScannersCheckbox.indeterminate = anyChecked && !allChecked;
        allScannersCheckbox.checked = allChecked;
    }
    
    // Advanced Options handling
    const advancedOptionsHeader = document.querySelector('.advanced-options-header');
    const advancedOptionsCollapse = document.getElementById('advancedOptionsCollapse');
    const chevronIcon = advancedOptionsHeader?.querySelector('.bi-chevron-down');
    const wafEvasionCheckbox = document.getElementById('wafEvasion');
    const randomizeHeadersCheckbox = document.getElementById('randomizeHeaders');
    const rotateUserAgentCheckbox = document.getElementById('rotateUserAgent');
    
    // Initialize Bootstrap collapse
    let advancedCollapse;
    if (advancedOptionsCollapse) {
        advancedCollapse = new bootstrap.Collapse(advancedOptionsCollapse, {
            toggle: false
        });
    }
    
    // Toggle advanced options section
    if (advancedOptionsHeader) {
        advancedOptionsHeader.addEventListener('click', function() {
            if (advancedCollapse) {
                advancedCollapse.toggle();
                if (chevronIcon) {
                    if (advancedOptionsCollapse.classList.contains('show')) {
                        chevronIcon.classList.remove('bi-chevron-down');
                        chevronIcon.classList.add('bi-chevron-up');
                    } else {
                        chevronIcon.classList.remove('bi-chevron-up');
                        chevronIcon.classList.add('bi-chevron-down');
                    }
                }
            }
        });
    }
    
    // JavaScript rendering options
    if (jsEnabledCheckbox && jsOptionsDiv) {
        // Show/hide JS options based on checkbox state
        jsEnabledCheckbox.addEventListener('change', function() {
            jsOptionsDiv.style.display = this.checked ? 'block' : 'none';
            
            // Auto-expand advanced options when JavaScript rendering is enabled
            if (this.checked && advancedOptionsCollapse && !advancedOptionsCollapse.classList.contains('show') && advancedCollapse) {
                advancedCollapse.show();
                if (chevronIcon) {
                    chevronIcon.classList.remove('bi-chevron-down');
                    chevronIcon.classList.add('bi-chevron-up');
                }
            }
        });
        
        // Initialize JS options visibility
        jsOptionsDiv.style.display = jsEnabledCheckbox.checked ? 'block' : 'none';
    }
    
    // WAF Bypass mode handling
    if (wafEvasionCheckbox && wafOptionsDiv) {
        // Show/hide WAF options based on checkbox state
        wafEvasionCheckbox.addEventListener('change', function() {
            wafOptionsDiv.style.display = this.checked ? 'block' : 'none';
            
            // Auto-check related options when WAF bypass is enabled
            if (this.checked) {
                if (randomizeHeadersCheckbox) randomizeHeadersCheckbox.checked = true;
                if (rotateUserAgentCheckbox) rotateUserAgentCheckbox.checked = true;
                
                // Auto-expand advanced options when WAF bypass is enabled
                if (advancedOptionsCollapse && !advancedOptionsCollapse.classList.contains('show') && advancedCollapse) {
                    advancedCollapse.show();
                    if (chevronIcon) {
                        chevronIcon.classList.remove('bi-chevron-down');
                        chevronIcon.classList.add('bi-chevron-up');
                    }
                }
            }
        });
        
        // Initialize WAF options visibility
        wafOptionsDiv.style.display = wafEvasionCheckbox.checked ? 'block' : 'none';
    }
    
    // Add event listeners for scanner checkboxes
    if (allScannersCheckbox) {
        allScannersCheckbox.addEventListener('change', handleAllScannersCheckbox);
        
        // Initialize the all scanners checkbox
        handleAllScannersCheckbox();
    }
    
    if (scannerCheckboxes.length > 0) {
        scannerCheckboxes.forEach(checkbox => {
            checkbox.addEventListener('change', updateAllScannersCheckbox);
        });
    }

    // Handle form submission
    if (scanFormElement) {
        scanFormElement.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            // Get form values
            const targetUrl = document.getElementById('targetUrl').value;
            const maxPages = document.getElementById('maxPages').value;
            const delay = document.getElementById('delay').value;
            const userAgent = document.getElementById('userAgent').value;
            
            // Get JavaScript rendering options
            const jsEnabled = document.getElementById('jsEnabled')?.checked || false;
            const browserTimeout = jsEnabled ? parseInt(document.getElementById('browserTimeout')?.value || 30000) : 30000;
            const waitForIdle = jsEnabled ? document.getElementById('waitForIdle')?.checked || true : true;
            
            // Get WAF evasion and session management options
            const wafEvasion = document.getElementById('wafEvasion')?.checked || false;
            const rotateUserAgent = document.getElementById('rotateUserAgent')?.checked || false;
            const randomizeHeaders = document.getElementById('randomizeHeaders')?.checked || false;
            const maintainSession = document.getElementById('maintainSession')?.checked || true;
            const handleCsrf = document.getElementById('handleCsrf')?.checked || true;
            
            // Validate User-Agent
            if (!validateUserAgent(userAgent)) {
                return;
            }
            
            // Get selected scanners
            const selectedScanners = [];
            document.querySelectorAll('.scanner-checkbox:checked').forEach(checkbox => {
                selectedScanners.push(checkbox.id.replace('Scanner', ''));
            });
            
            // Show results card
            resultsCard.style.display = 'block';
            
            // Clear previous results
            scanStats.innerHTML = `
                <div class="alert alert-info">
                    <div class="d-flex align-items-center">
                        <div class="spinner-border spinner-border-sm me-2" role="status">
                            <span class="visually-hidden">Loading...</span>
                        </div>
                        <span>Scanning ${targetUrl}${jsEnabled ? ' with JavaScript rendering' : ''}...</span>
                    </div>
                </div>
            `;
            vulnerabilities.innerHTML = '';
            
            try {
                // Make API request
                const response = await fetch(`${API_URL}/scan`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-API-Key': API_KEY
                    },
                    body: JSON.stringify({
                        target_url: targetUrl,
                        scanners: selectedScanners,
                        max_pages: parseInt(maxPages),
                        delay: parseFloat(delay),
                        user_agent: userAgent || undefined,
                        js_enabled: jsEnabled,
                        browser_timeout: browserTimeout,
                        wait_for_idle: waitForIdle,
                        waf_evasion: wafEvasion,
                        rotate_user_agent: rotateUserAgent,
                        randomize_headers: randomizeHeaders,
                        maintain_session: maintainSession,
                        handle_csrf: handleCsrf
                    })
                });

                if (!response.ok) {
                if (response.status === 403) {
                    localStorage.removeItem('secscan_api_key');
                    throw new Error('Invalid API key. Please refresh the page and enter a valid API key.');
                }
                const error = await response.json();
                throw new Error(error.detail || 'Scan failed');
            }

            const result = await response.json();
            updateTerminal('Scan completed successfully', 'info');
            displayResults(result);

        } catch (error) {
            updateTerminal(`Error: ${error.message}`, 'error');
        }
    });
}

// Display results
async function displayResults(result) {
    // Clear previous results
    if (scanStats) scanStats.innerHTML = '';
    if (vulnerabilities) vulnerabilities.innerHTML = '';
    if (resultsCard) resultsCard.style.display = 'block';

    // Display statistics
    const stats = result.stats || {};
    if (scanStats) {
        const scanDuration = result.stats.scan_duration || '0';
        const scanTime = new Date().toLocaleTimeString();
        
        let statsHtml = `
            <div class="alert alert-success">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h5 class="mb-0"><i class="bi bi-check-circle me-2"></i>Scan Completed</h5>
                    <span class="scan-timestamp"><i class="bi bi-clock me-1"></i>${scanTime} • ${scanDuration}s</span>
                </div>
                <div class="row mt-4">
                    <div class="col-md-3">
                        <div class="stat-card">
                            <div class="stat-card-icon">
                                <i class="bi bi-file-earmark-text"></i>
                            </div>
                            <div class="stat-card-content">
                                <div class="stat-card-value">${result.stats.pages_crawled}</div>
                                <div class="stat-card-label">Pages Crawled</div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="stat-card">
                            <div class="stat-card-icon">
                                <i class="bi bi-link-45deg"></i>
                            </div>
                            <div class="stat-card-content">
                                <div class="stat-card-value">${result.stats.links_found}</div>
                                <div class="stat-card-label">Links Found</div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="stat-card">
                            <div class="stat-card-icon">
                                <i class="bi bi-ui-checks"></i>
                            </div>
                            <div class="stat-card-content">
                                <div class="stat-card-value">${result.stats.forms_found}</div>
                                <div class="stat-card-label">Forms Found</div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="stat-card">
                            <div class="stat-card-icon" style="background-color: ${result.stats.js_enabled ? 'rgba(40, 167, 69, 0.15)' : 'rgba(108, 117, 125, 0.15)'}">
                                <i class="bi bi-browser-chrome" style="color: ${result.stats.js_enabled ? 'var(--success-color)' : 'var(--secondary-color)'}"></i>
                            </div>
                            <div class="stat-card-content">
                                <div class="stat-card-value">${result.stats.js_enabled ? 'Enabled' : 'Disabled'}</div>
                                <div class="stat-card-label">JS Rendering</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;

        // Display form analysis if JavaScript rendering was enabled
        if (result.form_analysis && result.form_analysis.length > 0) {
            statsHtml += `
                <div class="form-analysis-container mt-4">
                    <div class="form-analysis-header">
                        <h5><i class="bi bi-code-slash me-2"></i>JavaScript Form Analysis</h5>
                    </div>
                    <div class="form-analysis-content">
                        <div class="table-responsive">
                            <table class="form-analysis-table">
                                <thead>
                                    <tr>
                                        <th>Page URL</th>
                                        <th>Form Identifier</th>
                                        <th>Submission Type</th>
                                        <th>Action</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${result.form_analysis.map(form => `
                                        <tr>
                                            <td class="text-truncate" title="${form.url}">${form.url}</td>
                                            <td>${form.form_id || form.form_class || 'Unknown'}</td>
                                            <td>
                                                <span class="submission-type-badge ${form.submission_type === 'javascript' ? 'javascript' : 'standard'}">
                                                    ${form.submission_type}
                                                </span>
                                            </td>
                                            <td class="text-truncate" title="${form.action}">${form.action || 'JavaScript event handler'}</td>
                                        </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
        }

        scanStats.innerHTML = statsHtml;
    }

    // Display vulnerabilities
    if (vulnerabilities) {
        const vulns = result.vulnerabilities || [];
        if (vulns.length > 0) {
            // Count vulnerabilities by severity
            const criticalCount = vulns.filter(v => v.severity === 'critical').length;
            const highCount = vulns.filter(v => v.severity === 'high').length;
            const mediumCount = vulns.filter(v => v.severity === 'medium').length;
            const lowCount = vulns.filter(v => v.severity === 'low').length;
            
            // Group vulnerabilities by type
            const vulnsByType = {};
            vulns.forEach(vuln => {
                // Extract base type (XSS, SQL Injection, etc.)
                const baseType = vuln.type.split(' ')[0].toUpperCase();
                if (!vulnsByType[baseType]) {
                    vulnsByType[baseType] = [];
                }
                vulnsByType[baseType].push(vuln);
            });
            
            let vulnsHtml = `
                <div class="vulnerabilities-header mb-4">
                    <div class="d-flex justify-content-between align-items-center mb-3">
                        <h5 class="mb-0"><i class="bi bi-shield-exclamation me-2"></i>Found ${vulns.length} Vulnerabilities</h5>
                        <div class="severity-summary">
                            ${criticalCount > 0 ? `<span class="severity-badge critical"><i class="bi bi-exclamation-octagon-fill me-1"></i>${criticalCount} Critical</span>` : ''}
                            ${highCount > 0 ? `<span class="severity-badge high"><i class="bi bi-exclamation-triangle-fill me-1"></i>${highCount} High</span>` : ''}
                            ${mediumCount > 0 ? `<span class="severity-badge medium"><i class="bi bi-exclamation-circle me-1"></i>${mediumCount} Medium</span>` : ''}
                            ${lowCount > 0 ? `<span class="severity-badge low"><i class="bi bi-info-circle me-1"></i>${lowCount} Low</span>` : ''}
                        </div>
                    </div>
                </div>
            `;
            
            // Add each vulnerability group
            Object.entries(vulnsByType).forEach(([vulnType, typeVulns]) => {
                // Get the highest severity for this vulnerability type
                const severityOrder = { 'critical': 4, 'high': 3, 'medium': 2, 'low': 1 };
                const highestSeverity = typeVulns.reduce((highest, vuln) => {
                    return severityOrder[vuln.severity] > severityOrder[highest] ? vuln.severity : highest;
                }, 'low');
                
                // Get severity icon based on highest severity level
                let severityIcon = 'bi-info-circle';
                if (highestSeverity === 'critical') severityIcon = 'bi-exclamation-octagon-fill';
                else if (highestSeverity === 'high') severityIcon = 'bi-exclamation-triangle-fill';
                else if (highestSeverity === 'medium') severityIcon = 'bi-exclamation-circle';
                
                vulnsHtml += `
                <div class="vulnerability-group ${highestSeverity}">
                    <div class="vulnerability-group-header" onclick="toggleVulnerabilityGroup(this)">
                        <h6>
                            <i class="bi ${severityIcon} me-2"></i>
                            ${vulnType} (${typeVulns.length} ${typeVulns.length === 1 ? 'instance' : 'instances'})
                            <i class="bi bi-chevron-down ms-2 toggle-icon"></i>
                        </h6>
                    </div>
                    <div class="vulnerability-group-content">
                `;
                
                // Add each vulnerability in this group
                typeVulns.forEach((vuln, index) => {
                    // Generate AI recommendations based on vulnerability type
                    let aiRecommendations = [];
                    let confidenceScore = Math.floor(Math.random() * 30) + 70; // Random score between 70-99 for demo
                    let preventionScore = Math.floor(Math.random() * 40) + 60; // Random score between 60-99 for demo
                    
                    if (vuln.type.toLowerCase().includes('sql')) {
                        aiRecommendations = [
                            'Use parameterized queries or prepared statements',
                            'Implement input validation and sanitization',
                            'Apply principle of least privilege for database accounts'
                        ];
                    } else if (vuln.type.toLowerCase().includes('xss')) {
                        aiRecommendations = [
                            'Implement Content Security Policy (CSP)',
                            'Use context-specific output encoding',
                            'Sanitize user input before rendering'
                        ];
                    } else if (vuln.type.toLowerCase().includes('csrf')) {
                        aiRecommendations = [
                            'Implement anti-CSRF tokens',
                            'Use SameSite cookie attribute',
                            'Verify request origin headers'
                        ];
                    } else {
                        aiRecommendations = [
                            'Apply input validation and sanitization',
                            'Implement proper error handling',
                            'Follow the principle of least privilege'
                        ];
                    }
                    
                    // Get severity icon based on severity level
                    let vulnSeverityIcon = 'bi-info-circle';
                    if (vuln.severity === 'critical') vulnSeverityIcon = 'bi-exclamation-octagon-fill';
                    else if (vuln.severity === 'high') vulnSeverityIcon = 'bi-exclamation-triangle-fill';
                    else if (vuln.severity === 'medium') vulnSeverityIcon = 'bi-exclamation-circle';
                    
                    vulnsHtml += `
                    <div class="vulnerability-item ${vuln.severity}">
                        <h6>
                            <i class="bi ${vulnSeverityIcon} me-2"></i>
                            ${vuln.type.toUpperCase()} at ${vuln.url}
                        </h6>
                        <div class="vulnerability-details">
                            <p><strong>Parameter:</strong> ${vuln.param || 'N/A'}</p>
                            <p><strong>Payload:</strong> ${vuln.payload || 'N/A'}</p>
                            <p><strong>Evidence:</strong> ${vuln.evidence || 'N/A'}</p>
                            <p>
                                <strong>Severity:</strong> <span class="severity ${vuln.severity}">${vuln.severity}</span>
                                <span class="confidence">Confidence ${confidenceScore}%</span>
                                <span class="prevention-score">Prevention ${preventionScore}%</span>
                            </p>
                        </div>
                        <div class="recommendations mt-3">
                            <h6><i class="bi bi-lightbulb-fill me-2"></i>AI Recommendations</h6>
                            <ul class="list-group">
                    `;
                    
                    // Add recommendations
                    aiRecommendations.forEach(rec => {
                        vulnsHtml += `
                        <li class="list-group-item">
                            <i class="bi bi-check-circle me-2"></i>${rec}
                        </li>
                        `;
                    });
                    
                    vulnsHtml += `
                            </ul>
                        </div>
                    </div>
                    `;
                });
                
                vulnsHtml += `
                    </div>
                </div>
                `;
            });
            
            vulnerabilities.innerHTML = vulnsHtml;
        } else {
            vulnerabilities.innerHTML = `
                <div class="alert alert-success">
                    <i class="bi bi-check-circle me-2"></i>No vulnerabilities found
                </div>
            `;
        }
    }
}

// Toggle vulnerability group dropdown - make it globally accessible
window.toggleVulnerabilityGroup = function(header) {
    const content = header.nextElementSibling;
    const toggleIcon = header.querySelector('.toggle-icon');
    
    // Toggle content visibility
    if (content.style.maxHeight) {
        content.style.maxHeight = null;
        toggleIcon.classList.remove('bi-chevron-up');
        toggleIcon.classList.add('bi-chevron-down');
    } else {
        content.style.maxHeight = content.scrollHeight + "px";
        toggleIcon.classList.remove('bi-chevron-down');
        toggleIcon.classList.add('bi-chevron-up');
    }
}

// Add test functionality
if (testButton) {
    testButton.addEventListener('click', async () => {
        try {
            // Clear previous results
            clearResults();

            // Update terminal with test scan messages
            updateTerminal('Starting test scan...', 'info');
            updateTerminal('Target: https://example.com', 'info');
            updateTerminal('Selected scanners: xss, sqli, ssrf, csrf, ssti, cmdInjection, pathTraversal, xxe', 'info');

            // Simulate crawling with proper message format
            updateTerminal('Crawling completed. Found 5 pages in 2.5 seconds', 'info');
            updateTerminal('Running XSS scanner on https://example.com/search', 'info');
            updateTerminal('Running SQLI scanner on https://example.com/login', 'info');

            // Create sample vulnerabilities
            const sampleResult = {
                scan_id: 'test_scan_123',
                stats: {
                    pages_crawled: 5,
                    links_found: 15,
                    forms_found: 3,
                    js_enabled: true
                },
                form_analysis: [
                    {
                        url: 'https://example.com/login',
                        form_id: 'loginForm',
                        submission_type: 'javascript',
                        action: 'JavaScript event handler'
                    },
                    {
                        url: 'https://example.com/contact',
                        form_id: 'contactForm',
                        submission_type: 'unknown',
                        action: ''
                    }
                ],
                vulnerabilities: [
                    {
                        type: 'SQL Injection',
                        url: 'https://example.com/login',
                        payload: "' OR '1'='1",
                        evidence: 'SQL error detected: MySQL server version for the right syntax',
                        severity: 'critical',
                        param: 'username',
                        method: 'POST'
                    },
                    {
                        type: 'Cross-Site Scripting (XSS)',
                        url: 'https://example.com/search',
                        payload: '<script>alert("XSS")</script>',
                        evidence: 'Payload was reflected in the response',
                        severity: 'high',
                        param: 'q',
                        method: 'GET'
                    }
                ]
            };

            // Display results
            updateTerminal('Scan completed successfully', 'info');
            displayResults(sampleResult);

        } catch (error) {
            updateTerminal(`Test error: ${error.message}`, 'error');
        }
    });
}
});
