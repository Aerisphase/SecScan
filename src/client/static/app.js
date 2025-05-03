document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const scanForm = document.getElementById('scanForm');
    const resultsCard = document.getElementById('resultsCard');
    const scanStats = document.getElementById('scanStats');
    const vulnerabilities = document.getElementById('vulnerabilities');
    const advancedOptions = document.getElementById('advancedOptions');
    const exportResultsBtn = document.getElementById('exportResults');
    const clearResultsBtn = document.getElementById('clearResults');
    const randomizeUserAgentBtn = document.getElementById('randomizeUserAgent');
    const wafBypassCheckbox = document.getElementById('wafBypass');

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
    exportResultsBtn.addEventListener('click', exportResults);
    clearResultsBtn.addEventListener('click', clearResults);
    randomizeUserAgentBtn.addEventListener('click', randomizeUserAgent);
    
    // Handle form submission
    scanForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        // Show terminal and clear previous results
        clearResults();
        terminalContent.innerHTML = '';
        
        // Get form values
        const targetUrl = document.getElementById('targetUrl').value;
        const scanType = document.getElementById('scanType').value;
        const maxPages = document.getElementById('maxPages').value;
        const delay = document.getElementById('delay').value;
        const userAgent = document.getElementById('userAgent').value;
        const wafBypass = document.getElementById('wafBypass').checked;
        
        // Validate user agent if provided
        if (userAgent && !validateUserAgent(userAgent)) {
            return;
        }
        
        // Prepare request data
        const requestData = {
            target_url: targetUrl,
            scan_type: scanType,
            max_pages: parseInt(maxPages),
            delay: parseFloat(delay),
            waf_bypass: wafBypass
        };
        
        if (userAgent) {
            requestData.user_agent = userAgent;
        }
        
        // Update terminal with scan info
        updateTerminal(`Starting scan of ${targetUrl}`, 'info');
        if (wafBypass) {
            updateTerminal('WAF bypass mode enabled - Using evasion techniques', 'warning');
        }
        
        try {
            // Connect to WebSocket for real-time logs
            connectWebSocket();
            
            // Send scan request
            const response = await fetch(`${API_URL}/scan`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    [API_KEY_NAME]: API_KEY
                },
                body: JSON.stringify(requestData)
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            
            const result = await response.json();
            
            // Display results
            displayResults(result);
            
        } catch (error) {
            handleApiError(error);
        }
    });

    // Advanced options toggle
    advancedOptions.addEventListener('change', (e) => {
        const advancedFields = document.querySelectorAll('.advanced-field');
        advancedFields.forEach(field => {
            field.style.display = e.target.checked ? 'block' : 'none';
        });
    });

    // Terminal Management
    let isTerminalPaused = false;
    const terminalContent = document.getElementById('terminalContent');
    const terminalStatus = document.querySelector('.terminal-status');
    let ws = null;

    // Track connection attempts to prevent rapid reconnection cycles
let connectionAttempts = 0;
let lastConnectionTime = 0;
let reconnectTimer = null;
let pingTimer = null;
let scanInProgress = false;

function connectWebSocket() {
        // Clear any existing timers
        if (pingTimer) {
            clearInterval(pingTimer);
            pingTimer = null;
        }
        
        if (reconnectTimer) {
            clearTimeout(reconnectTimer);
            reconnectTimer = null;
        }
        
        // Prevent rapid reconnection attempts
        const now = Date.now();
        if (now - lastConnectionTime < 2000 && connectionAttempts > 2) {
            console.log(`Delaying reconnection attempt (${connectionAttempts} attempts in quick succession)`); 
            reconnectTimer = setTimeout(() => {
                connectionAttempts = 0;
                connectWebSocket();
            }, 5000);
            return;
        }
        
        lastConnectionTime = now;
        connectionAttempts++;
        
        // Clean up existing connection if any
        if (ws) {
            try {
                // Only close if not already closing or closed
                if (ws.readyState !== WebSocket.CLOSING && ws.readyState !== WebSocket.CLOSED) {
                    ws.close();
                }
            } catch (e) {
                console.error('Error closing existing WebSocket:', e);
            }
            ws = null;
        }

        try {
            // Update UI to show connecting state
            terminalStatus.textContent = 'Connecting...';
            terminalStatus.style.backgroundColor = '#ff9800';
            
            // Create new WebSocket connection with no protocol specified
            ws = new WebSocket(WS_URL);
            
            let connectionTimeout = setTimeout(() => {
                if (ws && ws.readyState !== WebSocket.OPEN) {
                    updateTerminal('Connection timeout, retrying...', 'warning');
                    try {
                        ws.close();
                    } catch (e) {
                        console.error('Error closing timed out connection:', e);
                    }
                    // Reset connection attempts after timeout
                    connectionAttempts = 0;
                    setTimeout(() => connectWebSocket(), 3000);
                }
            }, 5000);
            
            ws.onopen = () => {
                clearTimeout(connectionTimeout);
                updateTerminal('Connected to server', 'info');
                terminalStatus.textContent = 'Connected';
                terminalStatus.style.backgroundColor = '#4CAF50';
                
                // Send initial ping to verify connection
                try {
                    ws.send(JSON.stringify({ type: 'ping' }));
                } catch (e) {
                    console.error('Error sending initial ping:', e);
                }
                
                // Set up a more aggressive ping interval during scanning
                if (scanInProgress) {
                    console.log('Setting up aggressive ping interval for scan');
                    if (pingTimer) clearInterval(pingTimer);
                    pingTimer = setInterval(() => {
                        if (ws && ws.readyState === WebSocket.OPEN) {
                            try {
                                ws.send(JSON.stringify({ type: 'ping' }));
                                console.log('Sent aggressive ping during scan');
                            } catch (e) {
                                console.error('Error sending aggressive ping:', e);
                            }
                        }
                    }, 2000); // Send ping every 2 seconds during scanning
                }
            };
            
            ws.onclose = (event) => {
                clearTimeout(connectionTimeout);
                
                // Don't show warning for normal closure
                if (event.code !== 1000) {
                    updateTerminal(`Disconnected from server (${event.code})`, 'warning');
                }
                
                terminalStatus.textContent = 'Disconnected';
                terminalStatus.style.backgroundColor = '#f44336';
                
                // Clear any existing reconnect timer
                clearTimeout(reconnectTimer);
                
                // If we've had too many rapid reconnection attempts, delay longer
                if (connectionAttempts > 5) {
                    const backoffDelay = Math.min(5000 * Math.pow(1.5, Math.min(connectionAttempts - 5, 5)), 30000);
                    updateTerminal(`Too many connection attempts, backing off for ${Math.round(backoffDelay/1000)} seconds...`, 'warning');
                    reconnectTimer = setTimeout(() => {
                        connectionAttempts = 0;
                        connectWebSocket();
                    }, backoffDelay);
                } else {
                    // Normal reconnection with shorter delay
                    const reconnectDelay = 3000;
                    updateTerminal(`Reconnecting in ${Math.round(reconnectDelay/1000)} seconds...`, 'info');
                    reconnectTimer = setTimeout(connectWebSocket, reconnectDelay);
                }
            };
            
            ws.onerror = (error) => {
                // Just log the error, onclose will handle reconnection
                console.error('WebSocket error:', error);
                updateTerminal(`WebSocket error: ${error.message || 'undefined'}`, 'error');
            };
            
            ws.onmessage = (event) => {
                // Reset reconnect delay on successful message
                window.lastReconnectDelay = 1000;
                
                try {
                    const data = JSON.parse(event.data);
                    
                    if (data.type === 'pong') {
                        // Pong received, connection is good
                        return;
                    }
                    
                    if (data.type === 'ping') {
                        // Respond to ping immediately
                        ws.send(JSON.stringify({ type: 'pong' }));
                        return;
                    }
                    
                    if (data.type === 'connected') {
                        updateTerminal(data.message, 'info');
                        return;
                    }
                    
                    // Track scan status based on message content
                    if (data.message) {
                        // Check for scan start/end messages
                        if (data.message.includes('Starting scan') || 
                            data.message.includes('Scan initiated')) {
                            console.log('Scan started - enabling aggressive ping');
                            scanInProgress = true;
                            
                            // Set up aggressive ping for scan
                            if (pingTimer) clearInterval(pingTimer);
                            pingTimer = setInterval(() => {
                                if (ws && ws.readyState === WebSocket.OPEN) {
                                    try {
                                        ws.send(JSON.stringify({ type: 'ping' }));
                                    } catch (e) {
                                        console.error('Error sending scan ping:', e);
                                    }
                                }
                            }, 2000);
                        } 
                        else if (data.message.includes('Scan completed') || 
                                 data.message.includes('Scan failed') || 
                                 data.message.includes('Scan error')) {
                            console.log('Scan ended - disabling aggressive ping');
                            scanInProgress = false;
                            
                            // Return to normal ping interval
                            if (pingTimer) {
                                clearInterval(pingTimer);
                                pingTimer = setInterval(() => {
                                    if (ws && ws.readyState === WebSocket.OPEN) {
                                        try {
                                            ws.send(JSON.stringify({ type: 'ping' }));
                                        } catch (e) {
                                            console.error('Error sending normal ping:', e);
                                        }
                                    }
                                }, 5000);
                            }
                        }
                        
                        // Display the message
                        updateTerminal(data.message, data.level || 'info');
                    }
                } catch (e) {
                    console.error('Error parsing message:', e, event.data);
                    updateTerminal('Error parsing message from server', 'error');
                }
            };
        } catch (error) {
            console.error('Failed to create WebSocket:', error);
            updateTerminal(`Failed to create WebSocket connection: ${error.message || 'undefined'}`, 'error');
            setTimeout(connectWebSocket, 5000);
        }
    }

    function updateTerminal(message, type = 'info') {
        if (isTerminalPaused) return;
        
        const timestamp = new Date().toLocaleTimeString();
        const line = document.createElement('div');
        line.className = `terminal-line ${type}`;
        
        const timestampSpan = document.createElement('span');
        timestampSpan.className = 'terminal-timestamp';
        timestampSpan.textContent = `[${timestamp}]`;
        
        const messageSpan = document.createElement('span');
        
        // Format page processing messages
        if (message && typeof message === 'string') {
            if (message.includes('Processed page')) {
                const parts = message.split(' ');
                const pageNumber = parts[parts.length - 1].replace(/[()]/g, '');
                const url = parts.slice(3, -1).join(' ');
                
                messageSpan.innerHTML = `
                    <span class="page-number">${pageNumber}</span>
                    <span class="page-url">${url}</span>
                `;
                line.classList.add('page-processed');
            }
            // Format scanner messages
            else if (message.includes('Running') && (message.includes('XSS') || message.includes('SQLI'))) {
                const scannerType = message.includes('XSS') ? 'XSS' : 'SQLI';
                const url = message.split(' on ')[1];
                
                messageSpan.innerHTML = `
                    <span class="scanner-badge ${scannerType.toLowerCase()}">${scannerType}</span>
                    <span class="scanner-url">${url}</span>
                `;
                line.classList.add('scanner-running');
            }
            // Format crawling completion message
            else if (message.includes('Crawling completed')) {
                const time = message.split(' in ')[1]?.split(' seconds')[0] || '0';
                const pages = message.split('Found ')[1]?.split(' pages')[0] || '0';
                
                messageSpan.innerHTML = `
                    <span class="completion-message">
                        Crawling completed in <span class="time">${time}s</span>
                        <br>
                        Found <span class="pages">${pages}</span> pages
                    </span>
                `;
                line.classList.add('crawl-complete');
            }
            else {
                messageSpan.textContent = message;
            }
        } else {
            messageSpan.textContent = message?.toString() || 'Unknown message';
        }
        
        line.appendChild(timestampSpan);
        line.appendChild(messageSpan);
        terminalContent.appendChild(line);
        
        // Auto-scroll to bottom
        terminalContent.scrollTop = terminalContent.scrollHeight;
    }

    function clearTerminal() {
        terminalContent.innerHTML = '';
        updateTerminal('Terminal cleared', 'info');
    }

    function toggleTerminalPause() {
        isTerminalPaused = !isTerminalPaused;
        const pauseButton = document.getElementById('pauseTerminal');
        pauseButton.innerHTML = isTerminalPaused ? 
            '<i class="bi bi-play-fill me-1"></i>Resume' : 
            '<i class="bi bi-pause-fill me-1"></i>Pause';
        terminalStatus.textContent = isTerminalPaused ? 'Paused' : 'Connected';
        terminalStatus.style.backgroundColor = isTerminalPaused ? '#ff9800' : '#4CAF50';
    }

    // Initialize WebSocket connection when the page loads
    connectWebSocket();
    
    // Event Listeners
    document.getElementById('clearTerminal').addEventListener('click', clearTerminal);
    document.getElementById('pauseTerminal').addEventListener('click', toggleTerminalPause);
    
    // Keep WebSocket connection alive with more frequent pings
    // Use a shorter interval for checking connection status
    setInterval(() => {
        if (!ws) {
            console.log('No WebSocket connection, attempting to connect...');
            connectWebSocket();
            return;
        }
        
        if (ws.readyState === WebSocket.OPEN) {
            // Only send ping if we haven't sent one recently
            const now = Date.now();
            if (!window.lastPingSent || now - window.lastPingSent > 8000) {
                try {
                    ws.send(JSON.stringify({ type: 'ping' }));
                    window.lastPingSent = now;
                } catch (error) {
                    console.error('Ping error:', error);
                    updateTerminal(`Failed to send ping: ${error.message || 'Connection lost'}`, 'error');
                    ws.close();
                    connectWebSocket();
                }
            }
        } else if (ws.readyState === WebSocket.CLOSED || ws.readyState === WebSocket.CLOSING) {
            // Try to reconnect if closed or closing
            updateTerminal('Connection closed, attempting to reconnect...', 'warning');
            connectWebSocket();
        }
    }, 5000); // Check every 5 seconds

    // Update scan form submission
    document.getElementById('scanForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const formData = {
            target_url: document.getElementById('targetUrl').value,
            scan_type: document.getElementById('scanType').value,
            max_pages: document.getElementById('maxPages').value,
            delay: document.getElementById('delay').value,
            user_agent: document.getElementById('userAgent').value || undefined
        };
        
        try {
            updateTerminal('Starting scan...', 'info');
            updateTerminal(`Target: ${formData.target_url}`, 'info');
            updateTerminal(`Scan type: ${formData.scan_type}`, 'info');
            
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

    // Display results
    function displayResults(result) {
        // Clear previous results
        scanStats.innerHTML = '';
        vulnerabilities.innerHTML = '';
        resultsCard.style.display = 'block';

        // Display statistics
        const stats = result.stats || {};
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

        // Display vulnerabilities with recommendations
        const vulns = result.vulnerabilities || [];
        if (vulns.length > 0) {
            vulnerabilities.innerHTML = `
                <h5 class="mb-3"><i class="bi bi-shield-exclamation me-2"></i>Found ${vulns.length} Vulnerabilities</h5>
                ${vulns.map((vuln, index) => `
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
                        <div class="recommendations mt-3">
                            <h6><i class="bi bi-lightbulb me-2"></i>Recommendations</h6>
                            <ul class="list-group list-group-flush">
                                ${vuln.recommendations.map(rec => `
                                    <li class="list-group-item">
                                        <i class="bi bi-check-circle me-2"></i>${rec}
                                    </li>
                                `).join('')}
                            </ul>
                        </div>
                    </div>
                `).join('')}
            `;
        } else {
            vulnerabilities.innerHTML = `
                <div class="alert alert-success">
                    <i class="bi bi-check-circle me-2"></i>No vulnerabilities found
                </div>
            `;
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

    // Advanced Options Management
    const advancedOptionsSwitch = document.getElementById('advancedOptions');
    const advancedFields = document.querySelectorAll('.advanced-field');
    const testButton = document.getElementById('testButton');

    function toggleAdvancedOptions() {
        const isAdvanced = advancedOptionsSwitch.checked;
        advancedFields.forEach(field => {
            field.style.display = isAdvanced ? 'block' : 'none';
        });
        // Show/hide test button
        testButton.style.display = isAdvanced ? 'block' : 'none';
        updateTerminal(`Advanced options ${isAdvanced ? 'enabled' : 'disabled'}`, 'info');
    }

    // Add advanced options event listener
    advancedOptionsSwitch.addEventListener('change', toggleAdvancedOptions);
    
    // Set initial state
    toggleAdvancedOptions();

    // Add test functionality
    document.getElementById('testButton').addEventListener('click', async () => {
        try {
            // Clear previous results
            clearResults();
            
            // Update terminal with test scan messages
            updateTerminal('Starting test scan...', 'info');
            updateTerminal('Target: https://example.com', 'info');
            updateTerminal('Scan type: full', 'info');
            
            // Simulate crawling with proper message format
            updateTerminal('Crawling completed. Found 5 pages in 2.5 seconds', 'info');
            updateTerminal('Running XSS scanner on https://example.com/search', 'info');
            updateTerminal('Running SQLI scanner on https://example.com/login', 'info');
            
            // Create sample vulnerabilities
            const sampleResult = {
                scan_id: 'test_scan_123',
                target_url: 'https://example.com',
                scan_type: 'full',
                timestamp: new Date().toISOString(),
                elapsed_time: 2.5,
                stats: {
                    pages_crawled: 5,
                    total_vulnerabilities: 3,
                    severity_counts: {
                        critical: 1,
                        high: 2,
                        medium: 0,
                        low: 0
                    }
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
                        type: 'XSS',
                        url: 'https://example.com/search',
                        payload: '<script>alert("XSS")</script>',
                        evidence: 'XSS payload found in response without encoding',
                        severity: 'high',
                        param: 'q',
                        method: 'GET',
                        recommendations: [
                            'Implement Content Security Policy (CSP)',
                            'Use output encoding',
                            'Validate and sanitize user input',
                            'Use modern frameworks with built-in XSS protection'
                        ],
                        prevention_score: 0.90,
                        confidence: 0.95
                    },
                    {
                        type: 'CSRF',
                        url: 'https://example.com/update-profile',
                        payload: 'Missing CSRF token',
                        evidence: 'No CSRF protection headers found',
                        severity: 'high',
                        param: 'profile_data',
                        method: 'POST',
                        recommendations: [
                            'Implement CSRF tokens',
                            'Use SameSite attribute for cookies',
                            'Verify origin headers',
                            'Implement double submit cookie pattern'
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

    // Add AI Analyze button event handler
    const aiAnalyzeBtn = document.getElementById('aiAnalyzeBtn');
    aiAnalyzeBtn.addEventListener('click', async () => {
        let vulnerabilities = [];
        try {
            if (window.lastScanResult && window.lastScanResult.vulnerabilities) {
                vulnerabilities = window.lastScanResult.vulnerabilities;
            } else {
                const vulnElements = document.querySelectorAll('.vulnerability-item');
                vulnElements.forEach(el => {
                    // Extract type from header text
                    let headerText = el.querySelector('h6, h3')?.textContent || '';
                    let typeMatch = headerText.match(/(SQL INJECTION|SQL Injection|XSS|CSRF)/i);
                    let vulnType = typeMatch ? (typeMatch[1].toUpperCase() === 'SQL INJECTION' ? 'SQL Injection' : typeMatch[1].toUpperCase()) : headerText.trim();
                    // Extract payload from the details section
                    let payload = '';
                    const payloadLabel = Array.from(el.querySelectorAll('p')).find(p => p.textContent.includes('Payload:'));
                    if (payloadLabel) {
                        payload = payloadLabel.textContent.replace('Payload:', '').trim();
                    } else {
                        payload = el.querySelector('code')?.textContent || '';
                    }
                    vulnerabilities.push({
                        type: vulnType,
                        evidence: el.textContent,
                        payload: payload
                    });
                });
            }
        } catch (e) {
            console.error('Could not gather vulnerabilities:', e);
            alert('Could not gather vulnerabilities for AI analysis.');
            return;
        }
        if (!vulnerabilities.length) {
            alert('No vulnerabilities found to analyze.');
            return;
        }
        try {
            aiAnalyzeBtn.disabled = true;
            aiAnalyzeBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Analyzing...';
            const response = await fetch('/ai-analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-API-Key': API_KEY
                },
                body: JSON.stringify({ vulnerabilities })
            });
            aiAnalyzeBtn.disabled = false;
            aiAnalyzeBtn.innerHTML = '<i class="bi bi-cpu me-1"></i>AI Analyze';
            if (!response.ok) {
                throw new Error('AI analysis failed');
            }
            const data = await response.json();
            showAIResultsModal(data.ai_results);
        } catch (e) {
            aiAnalyzeBtn.disabled = false;
            aiAnalyzeBtn.innerHTML = '<i class="bi bi-cpu me-1"></i>AI Analyze';
            alert('AI analysis failed: ' + e.message);
        }
    });

    // Modal for AI results
    function showAIResultsModal(results) {
        let modal = document.getElementById('aiResultsModal');
        if (!modal) {
            modal = document.createElement('div');
            modal.id = 'aiResultsModal';
            modal.className = 'modal fade';
            modal.tabIndex = -1;
            modal.innerHTML = `
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title"><i class="bi bi-cpu me-2"></i>AI Analysis Results</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body" id="aiResultsModalBody"></div>
                </div>
            </div>`;
            document.body.appendChild(modal);
        }
        const body = modal.querySelector('#aiResultsModalBody');
        body.innerHTML = results.map((r, i) => `
            <div class="mb-4 p-3 border rounded" style="background:#222; color:#fff;">
                <h6><i class="bi bi-exclamation-triangle me-1"></i>Vulnerability #${i+1}: <b>${r.type}</b></h6>
                <div><b>Risk Score:</b> ${(r.risk_score * 100).toFixed(1)}%</div>
                <div><b>Confidence:</b> ${(r.confidence * 100).toFixed(1)}%</div>
                <div><b>Recommendations:</b>
                    <ul>${r.recommendations.map(rec => `<li>${rec}</li>`).join('')}</ul>
                </div>
                <div><b>Payload Variations:</b>
                    <ul>${r.payload_variations.map(pv => `<li><code>${pv}</code></li>`).join('')}</ul>
                </div>
            </div>
        `).join('');
        // Show modal using Bootstrap
        const bsModal = new bootstrap.Modal(modal);
        bsModal.show();
    }
}); 