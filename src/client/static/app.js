document.addEventListener('DOMContentLoaded', () => {
    const scanForm = document.getElementById('scanForm');
    const resultsCard = document.getElementById('resultsCard');
    const scanStats = document.getElementById('scanStats');
    const vulnerabilities = document.getElementById('vulnerabilities');

    // API configuration
    const API_HOST = window.location.hostname;
    const API_PORT = window.location.port || '8001';  // Default to 8001 if not specified
    const API_URL = `https://${API_HOST}:${API_PORT}`;
    
    // Get API key from localStorage or prompt user
    let API_KEY = localStorage.getItem('secscan_api_key');
    if (!API_KEY) {
        API_KEY = prompt('Please enter your API key:');
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
            errorMessage = 'Could not connect to the server. Please make sure the server is running.';
        } else if (error.message.includes('401') || error.message.includes('403')) {
            errorMessage = 'Invalid API key. Please refresh the page and enter a valid API key.';
            localStorage.removeItem('secscan_api_key');
        }
        
        scanStats.innerHTML = `<div class="alert alert-danger">${errorMessage}</div>`;
    }

    scanForm.addEventListener('submit', async (e) => {
        e.preventDefault();

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
                    delay: parseFloat(document.getElementById('delay').value)
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
            </div>
        `;

        // Display vulnerabilities
        if (result.vulnerabilities && result.vulnerabilities.length > 0) {
            vulnerabilities.innerHTML = `
                <h5>Found ${result.vulnerabilities.length} vulnerabilities:</h5>
                ${result.vulnerabilities.map((vuln, index) => `
                    <div class="vulnerability-item ${vuln.severity || 'medium'}">
                        <h6>${index + 1}. ${vuln.type.toUpperCase()} at ${vuln.url}</h6>
                        <p><strong>Parameter:</strong> ${vuln.param || 'N/A'}</p>
                        <p><strong>Payload:</strong> ${vuln.payload || 'N/A'}</p>
                        <p><strong>Evidence:</strong> ${vuln.evidence || 'N/A'}</p>
                        <p><strong>Severity:</strong> ${vuln.severity || 'medium'}</p>
                    </div>
                `).join('')}
            `;
        } else {
            vulnerabilities.innerHTML = '<div class="alert alert-success">No vulnerabilities found!</div>';
        }
    }
}); 