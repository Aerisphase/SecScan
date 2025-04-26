document.addEventListener('DOMContentLoaded', () => {
    const scanForm = document.getElementById('scanForm');
    const resultsCard = document.getElementById('resultsCard');
    const scanStats = document.getElementById('scanStats');
    const vulnerabilities = document.getElementById('vulnerabilities');
    const logContainer = document.getElementById('logContainer');

    // API configuration
    const API_HOST = window.location.hostname;
    const API_PORT = window.location.port || '8001';  // Default to 8001 if not specified
    const API_URL = `https://${API_HOST}:${API_PORT}`;
    const WS_URL = `wss://${API_HOST}:${API_PORT}`;
    
    // WebSocket connection
    let ws = null;
    
    function connectWebSocket() {
        ws = new WebSocket(`${WS_URL}/ws/logs`);
        
        ws.onopen = () => {
            console.log('WebSocket connected');
        };
        
        ws.onmessage = (event) => {
            const logEntry = document.createElement('div');
            logEntry.className = 'log-entry';
            logEntry.textContent = event.data;
            logContainer.appendChild(logEntry);
            logContainer.scrollTop = logContainer.scrollHeight;
        };
        
        ws.onclose = () => {
            console.log('WebSocket disconnected');
            // Try to reconnect after 5 seconds
            setTimeout(connectWebSocket, 5000);
        };
        
        ws.onerror = (error) => {
            console.error('WebSocket error:', error);
        };
    }
    
    // Connect WebSocket when page loads
    connectWebSocket();
    
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

    // Function to handle API errors
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
        }
        
        scanStats.innerHTML = `<div class="alert alert-danger">${errorMessage}</div>`;
    }

    scanForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        // Clear previous logs
        logContainer.innerHTML = '';

        // Show loading state
        resultsCard.style.display = 'block';
        scanStats.innerHTML = '<div class="loading"><div class="spinner-border text-primary" role="status"></div></div>';
        vulnerabilities.innerHTML = '';

        try {
            // Start scan
            const response = await fetch(`${API_URL}/scan`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-API-Key': API_KEY
                },
                body: JSON.stringify({
                    target_url: document.getElementById('targetUrl').value,
                    scan_type: document.getElementById('scanType').value,
                    max_pages: parseInt(document.getElementById('maxPages').value),
                    delay: parseFloat(document.getElementById('delay').value),
                    user_agent: document.getElementById('userAgent').value || undefined
                })
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const result = await response.json();
            displayResults(result);

        } catch (error) {
            handleApiError(error);
        }
    });

    function displayResults(result) {
        // Display statistics
        scanStats.innerHTML = `
            <div class="stats-card">
                <div class="stats-item">
                    <span>Pages Crawled:</span>
                    <span>${result.stats.pages_crawled}</span>
                </div>
                <div class="stats-item">
                    <span>Links Found:</span>
                    <span>${result.stats.links_found}</span>
                </div>
                <div class="stats-item">
                    <span>Forms Found:</span>
                    <span>${result.stats.forms_found}</span>
                </div>
                ${result.stats.api_endpoints ? `
                <div class="stats-item">
                    <span>API Endpoints:</span>
                    <span>${result.stats.api_endpoints}</span>
                </div>
                ` : ''}
            </div>
        `;

        // Display vulnerabilities
        if (result.vulnerabilities && result.vulnerabilities.length > 0) {
            vulnerabilities.innerHTML = `
                <div class="vulnerabilities-list">
                    ${result.vulnerabilities.map((vuln, index) => `
                        <div class="vulnerability-item">
                            <h5>${index + 1}. ${vuln.type} Vulnerability</h5>
                            <p><strong>URL:</strong> ${vuln.url}</p>
                            <p><strong>Parameter:</strong> ${vuln.param}</p>
                            <p><strong>Payload:</strong> <code>${vuln.payload}</code></p>
                            <p><strong>Evidence:</strong> ${vuln.evidence}</p>
                            <p><strong>Severity:</strong> <span class="severity-${vuln.severity.toLowerCase()}">${vuln.severity}</span></p>
                        </div>
                    `).join('')}
                </div>
            `;
        } else {
            vulnerabilities.innerHTML = '<div class="alert alert-success">No vulnerabilities found!</div>';
        }
    }
}); 