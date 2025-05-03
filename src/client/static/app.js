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
        const results = {
            stats: scanStats.innerHTML,
            vulnerabilities: vulnerabilities.innerHTML
        };
        const blob = new Blob([JSON.stringify(results, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `secscan-results-${new Date().toISOString()}.json`;
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

    // Update scan form submission
    if (scanFormElement) {
        scanFormElement.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            // Get all selected scanners
            const selectedScanners = [];
            document.querySelectorAll('.scanner-checkbox').forEach(checkbox => {
                if (checkbox.checked) {
                    selectedScanners.push(checkbox.id.replace('Scanner', ''));
                }
            });
            
            // Validate at least one scanner is selected
            if (selectedScanners.length === 0) {
                updateTerminal('Error: Please select at least one scanner', 'error');
                return;
            }
        
            const formData = {
                target_url: document.getElementById('targetUrl').value,
                scanners: selectedScanners,
                max_pages: document.getElementById('maxPages').value,
                delay: document.getElementById('delay').value,
                user_agent: document.getElementById('userAgent').value || undefined
            };
            
            try {
                updateTerminal('Starting scan...', 'info');
                updateTerminal(`Target: ${formData.target_url}`, 'info');
                updateTerminal(`Selected scanners: ${formData.scanners.join(', ')}`, 'info');
                
                const response = await fetch('/scan', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-API-Key': API_KEY
                    },
                    body: JSON.stringify(formData)
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
            scanStats.innerHTML = `
                <div class="alert alert-info">
                    <h5><i class="bi bi-graph-up me-2"></i>Scan Statistics</h5>
                    <ul class="mb-0">
                        <li>Pages crawled: ${stats.pages_crawled || 0}</li>
                        <li>Links found: ${stats.links_found || 0}</li>
                        <li>Forms found: ${stats.forms_found || 0}</li>
                    </ul>
                </div>
            `;
        }

        // Display vulnerabilities with recommendations
        const vulns = result.vulnerabilities || [];
        if (vulnerabilities) {
            if (vulns.length > 0) {
                updateTerminal('Analyzing vulnerabilities with AI...', 'info');
                
                // Get AI analysis for vulnerabilities
                let aiResults = [];
                try {
                    const response = await fetch(`${API_URL}/ai-analyze`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-API-Key': API_KEY
                        },
                        body: JSON.stringify({ vulnerabilities: vulns })
                    });
                    
                    if (response.ok) {
                        const results = await response.json();
                        aiResults = results.ai_results || [];
                        updateTerminal('AI analysis completed successfully', 'info');
                    } else {
                        updateTerminal(`AI analysis failed: ${response.statusText}`, 'warning');
                    }
                } catch (error) {
                    console.error('AI analysis error:', error);
                    updateTerminal(`AI analysis error: ${error.message}`, 'warning');
                }
                
                vulnerabilities.innerHTML = `
                    <h5 class="mb-3"><i class="bi bi-shield-exclamation me-2"></i>Found ${vulns.length} Vulnerabilities</h5>
                    ${vulns.map((vuln, index) => {
                        // Find matching AI analysis if available
                        const aiAnalysis = aiResults.find(r => r.vulnerability_type === vuln.type) || null;
                        
                        return `
                        <div class="vulnerability-item ${vuln.severity}">
                            <h6>
                                <i class="bi bi-exclamation-triangle-fill me-2"></i>
                                ${vuln.type.toUpperCase()} at ${vuln.url}
                            </h6>
                            <div class="vulnerability-details">
                                <p><strong>Parameter:</strong> ${vuln.param || 'N/A'}</p>
                                <p><strong>Payload:</strong> ${vuln.payload || 'N/A'}</p>
                                <p><strong>Evidence:</strong> ${vuln.evidence || 'N/A'}</p>
                                <p><strong>Severity:</strong> <span class="severity">${vuln.severity}</span></p>
                                <p><strong>Prevention Score:</strong> ${(vuln.prevention_score * 100).toFixed(1)}%</p>
                                <p><strong>Confidence:</strong> ${(vuln.confidence * 100).toFixed(1)}%</p>
                            </div>
                            
                            ${aiAnalysis ? `
                            <div class="ai-explanation mt-3 bg-dark text-light p-3 rounded">
                                <h6 class="text-light"><i class="bi bi-cpu me-2"></i>AI Analysis</h6>
                                <p class="text-light">${aiAnalysis.explanation}</p>
                                <p><strong>Risk Level:</strong> <span class="badge bg-${aiAnalysis.risk_level === 'high' ? 'danger' : (aiAnalysis.risk_level === 'medium' ? 'warning' : 'info')}">${aiAnalysis.risk_level.toUpperCase()}</span></p>
                                <p><strong>AI Confidence:</strong> ${(aiAnalysis.confidence * 100).toFixed(1)}%</p>
                            </div>
                            ` : ''}
                            
                            <div class="recommendations mt-3">
                                <h6><i class="bi bi-cpu me-2"></i>AI Recommendations</h6>
                                <ul class="list-group list-group-flush bg-dark">
                                    ${aiAnalysis ? aiAnalysis.recommendations.map(rec => `
                                        <li class="list-group-item bg-dark text-light border-secondary">
                                            <i class="bi bi-cpu me-2 text-info"></i>${rec}
                                        </li>
                                    `).join('') : `
                                        <li class="list-group-item bg-dark text-light border-secondary">
                                            <i class="bi bi-info-circle me-2 text-warning"></i>AI analysis not available for this vulnerability type
                                        </li>
                                    `}
                                </ul>
                            </div>
                        </div>
                    `}).join('')}
                `;
            } else {
                vulnerabilities.innerHTML = `
                    <div class="alert alert-success">
                        <i class="bi bi-check-circle me-2"></i>No vulnerabilities found
                    </div>
                `;
            }
        }
    }

    // Add function to get preventive measures
    async function getPreventiveMeasures(codeContext) {
        try {
            const response = await fetch(`${API_URL}/preventive-measures`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-API-Key': API_KEY
                },
                body: JSON.stringify({ code_context: codeContext })
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            return data.measures;
        } catch (error) {
            console.error('Error getting preventive measures:', error);
            return [];
        }
    }

    // Add function to display preventive measures
    function displayPreventiveMeasures(measures) {
        if (!vulnerabilities) return;
        
        const preventiveMeasuresDiv = document.createElement('div');
        preventiveMeasuresDiv.className = 'preventive-measures mt-4';
        preventiveMeasuresDiv.innerHTML = `
            <h5><i class="bi bi-shield-check me-2"></i>Preventive Measures</h5>
            <ul class="list-group list-group-flush">
                ${measures.map(measure => `
                    <li class="list-group-item">
                        <i class="bi bi-check-circle me-2"></i>${measure}
                    </li>
                `).join('')}
            </ul>
        `;
        vulnerabilities.appendChild(preventiveMeasuresDiv);
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
                updateTerminal('Running SSRF scanner on https://example.com/fetch', 'info');
                updateTerminal('Running SSTI scanner on https://example.com/template', 'info');
                updateTerminal('Running Command Injection scanner on https://example.com/exec', 'info');
                updateTerminal('Running CSRF scanner on https://example.com/profile', 'info');
                
                // Create sample vulnerabilities
                const sampleResult = {
                    scan_id: 'test_scan_123',
                    target_url: 'https://example.com',
                    scan_type: 'custom',
                    timestamp: new Date().toISOString(),
                    elapsed_time: 2.5,
                    stats: {
                        pages_crawled: 5,
                        links_found: 15,
                        forms_found: 3
                    },
                    vulnerabilities: [
                        {
                            type: 'SQL Injection',
                            url: 'https://example.com/login',
                            payload: "' OR '1'='1",
                            evidence: 'SQL error detected: MySQL server version for the right syntax',
                            severity: 'critical',
                            param: 'username',
                            method: 'POST',
                            recommendations: [
                                'Use parameterized queries or prepared statements',
                                'Implement input validation',
                                'Use ORM frameworks',
                                'Apply the principle of least privilege'
                            ],
                            prevention_score: 0.95,
                            confidence: 0.98
                        },
                        {
                            type: 'Cross-Site Scripting (XSS)',
                            url: 'https://example.com/search',
                            payload: '<script>alert("XSS")</script>',
                            evidence: 'Payload was reflected in the response',
                            severity: 'high',
                            param: 'q',
                            method: 'GET',
                            recommendations: [
                                'Implement Content-Security-Policy (CSP)',
                                'Use context-aware output encoding',
                                'Sanitize user input',
                                'Use modern frameworks with built-in XSS protection'
                            ],
                            prevention_score: 0.85,
                            confidence: 0.92
                        }
                    ],
                    security_recommendations: [
                        'Missing X-Frame-Options header - Consider adding to prevent clickjacking',
                        'Missing X-Content-Type-Options header - Consider adding "nosniff"',
                        'Missing Content-Security-Policy header - Consider implementing CSP',
                        'Missing Strict-Transport-Security header - Consider adding HSTS'
                    ]
                };

                // Display results
                updateTerminal('Scan completed successfully', 'info');
                displayResults(sampleResult);
                
            } catch (error) {
                console.error('Test scan error:', error);
                updateTerminal(`Error: ${error.message}`, 'error');
            }
        });
    }

    // AI analysis is now automatically integrated into the vulnerability display
    // No separate AI Analyze button needed

    // AI analysis is now automatically integrated into the vulnerability display
    // No separate modal needed for AI results
});
