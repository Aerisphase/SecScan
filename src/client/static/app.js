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

    function connectWebSocket() {
        if (ws) {
            ws.close();
        }

        try {
            ws = new WebSocket(WS_URL, ['v1.secscan']);
            
            ws.onopen = () => {
                updateTerminal('Connected to server', 'info');
                terminalStatus.textContent = 'Connected';
                terminalStatus.style.backgroundColor = '#4CAF50';
            };
            
            ws.onclose = (event) => {
                updateTerminal(`Disconnected from server (${event.code})`, 'warning');
                terminalStatus.textContent = 'Disconnected';
                terminalStatus.style.backgroundColor = '#f44336';
                
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
                        // Handle advanced options messages
                        if (data.message.includes('Advanced options')) {
                            const isEnabled = data.message.includes('enabled');
                            updateTerminal(data.message, isEnabled ? 'success' : 'info');
                        } else {
                            updateTerminal(data.message, 'info');
                        }
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
        if (isTerminalPaused) return;
        
        const timestamp = new Date().toLocaleTimeString();
        const line = document.createElement('div');
        line.className = `terminal-line ${type}`;
        
        const timestampSpan = document.createElement('span');
        timestampSpan.className = 'terminal-timestamp';
        timestampSpan.textContent = `[${timestamp}]`;
        
        const messageSpan = document.createElement('span');
        
        // Format page processing messages
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
            const time = message.split(' in ')[1].split(' seconds')[0];
            const pages = message.split('Found ')[1].split(' pages')[0];
            
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

    function toggleAdvancedOptions() {
        const isAdvanced = advancedOptionsSwitch.checked;
        advancedFields.forEach(field => {
            field.style.display = isAdvanced ? 'block' : 'none';
        });
        updateTerminal(`Advanced options ${isAdvanced ? 'enabled' : 'disabled'}`, 'info');
    }

    // Add advanced options event listener
    advancedOptionsSwitch.addEventListener('change', toggleAdvancedOptions);
    
    // Set initial state
    toggleAdvancedOptions();
}); 