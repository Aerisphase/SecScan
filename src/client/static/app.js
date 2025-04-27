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
        terminalContent.innerHTML = '';
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
        else if (message.includes('Running') && message.includes('scanner')) {
            const scannerTypes = ['XSS', 'SQLI', 'CSRF', 'SSRF', 'XXE', 'IDOR', 'BROKEN_AUTH', 'SENSITIVE_DATA', 'SECURITY_MISCONFIG'];
            let scannerType = '';
            
            for (const type of scannerTypes) {
                if (message.includes(type)) {
                    scannerType = type;
                    break;
                }
            }
            
            if (scannerType) {
                const url = message.split(' on ')[1];
                messageSpan.innerHTML = `
                    <span class="scanner-badge ${scannerType.toLowerCase()}">${scannerType}</span>
                    <span class="scanner-url">${url}</span>
                `;
                line.classList.add('scanner-running');
            } else {
                messageSpan.textContent = message;
            }
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

    // Handle scan form submission
    scanForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        // Get form data
        const formData = new FormData(scanForm);
        const targetUrl = formData.get('targetUrl');
        const scanType = formData.get('scanType');
        const delay = parseFloat(formData.get('delay'));
        const maxPages = parseInt(formData.get('maxPages'));
        const userAgent = formData.get('userAgent');
        
        try {
            // Clear previous results
            clearResults();
            
            // Show loading state
            updateTerminal('Starting scan...', 'info');
            updateTerminal(`Target: ${targetUrl}`, 'info');
            updateTerminal(`Scan type: ${scanType}`, 'info');
            
            // Start scan
            const response = await fetch(`${API_URL}/scan`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-API-Key': API_KEY
                },
                body: JSON.stringify({
                    target_url: targetUrl,
                    scan_type: scanType,
                    delay: delay,
                    max_pages: maxPages,
                    user_agent: userAgent
                })
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const result = await response.json();
            
            // Update UI with results
            updateResults(result);
            
        } catch (error) {
            console.error('Scan error:', error);
            updateTerminal(`Error: ${error.message}`, 'error');
        }
    });

    // Update results display
    function updateResults(result) {
        if (!result || !result.results) return;
        
        const { results } = result;
        
        // Update stats
        scanStats.innerHTML = `
            <div class="stat-item">
                <span class="stat-label">Pages Crawled:</span>
                <span class="stat-value">${results.pages_crawled}</span>
            </div>
            <div class="stat-item">
                <span class="stat-label">Vulnerabilities Found:</span>
                <span class="stat-value">${results.vulnerabilities_found}</span>
            </div>
            <div class="stat-item">
                <span class="stat-label">Scan Duration:</span>
                <span class="stat-value">${((result.end_time - result.start_time) / 1000).toFixed(2)}s</span>
            </div>
        `;
        
        // Update vulnerabilities list
        if (results.vulnerabilities && results.vulnerabilities.length > 0) {
            vulnerabilities.innerHTML = results.vulnerabilities.map((vuln, index) => `
                <div class="vulnerability-item ${vuln.severity?.toLowerCase() || 'medium'}">
                    <h3>${index + 1}. ${vuln.type} at ${vuln.url}</h3>
                    <div class="vulnerability-details">
                        <p><strong>Parameter:</strong> ${vuln.param || 'N/A'}</p>
                        <p><strong>Payload:</strong> ${vuln.payload || 'N/A'}</p>
                        <p><strong>Evidence:</strong> ${vuln.evidence || 'N/A'}</p>
                        <p><strong>Severity:</strong> ${vuln.severity || 'medium'}</p>
                        <p><strong>Description:</strong> ${vuln.description || 'No description available'}</p>
                    </div>
                </div>
            `).join('');
        } else {
            vulnerabilities.innerHTML = '<div class="alert alert-success">No vulnerabilities found!</div>';
        }
        
        // Show results card
        resultsCard.style.display = 'block';
        
        // Scroll to results
        resultsCard.scrollIntoView({ behavior: 'smooth' });
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