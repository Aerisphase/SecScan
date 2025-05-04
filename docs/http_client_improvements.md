# HTTP Client Improvements

This document explains the enhanced HTTP client implementation in SecScan, focusing on WAF evasion techniques and improved session management.

## Overview

The enhanced HTTP client (`EnhancedHttpClient`) provides the following key improvements:

1. **WAF Evasion Techniques**
   - Request throttling and randomization
   - Rotating user agents and request patterns
   - Advanced evasion techniques for bypassing 403 Forbidden responses

2. **Cookie and Session Management**
   - Proper cookie jar support for maintaining sessions across requests
   - Automatic handling of CSRF tokens in forms

## Using the Enhanced HTTP Client

### Command Line Interface

You can enable these features via command line arguments:

```bash
python -m src.core.scanner --target https://example.com --waf-evasion --rotate-user-agent --maintain-session --handle-csrf
```

### Web Interface

In the web interface, you can find these options under the "WAF Evasion & Session Management" section:

- **Enable WAF evasion techniques**: Applies various techniques to bypass WAF protection
- **Rotate user agents**: Randomly changes user agent strings to avoid pattern detection
- **Maintain session cookies**: Preserves cookies across requests to maintain session state
- **Automatically handle CSRF tokens**: Extracts and includes CSRF tokens in form submissions

## WAF Evasion Techniques

### Request Throttling and Randomization

The enhanced client implements variable delays between requests to avoid triggering rate limiting:

```python
# Random delay between min and max values
delay = random.uniform(self.rate_limit_min, self.rate_limit_max)
```

### Rotating User Agents

The client can rotate between different user agent strings to avoid detection:

```python
USER_AGENTS = [
    # Chrome
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    # Firefox
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    # Safari
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
    # ...more agents...
]
```

### Header Randomization

The client randomizes HTTP headers to avoid pattern detection:

```python
# Add random Accept header variations
if random.random() > 0.5:
    accept_values = ['text/html', 'application/xhtml+xml', 'application/xml', 'image/webp', '*/*']
    random.shuffle(accept_values)
    # ...
```

### WAF Detection

The client can detect various WAF solutions and apply specific evasion techniques:

```python
# WAF detection patterns
self.waf_signatures = [
    ('Cloudflare', r'cloudflare|cf-ray|cf-chl-bypass|__cf_bm'),
    ('Akamai', r'akamai|ak_bmsc|bm_sv'),
    ('AWS WAF', r'aws-waf|awselb'),
    # ...more WAFs...
]
```

## Session Management

### Cookie Jar Support

The client maintains cookies across requests using a cookie jar:

```python
# Session and cookie management
self.session = requests.Session()
self.cookie_jar = RequestsCookieJar()
self.session.cookies = self.cookie_jar
```

### CSRF Token Handling

The client automatically extracts and includes CSRF tokens in form submissions:

```python
# Check for common CSRF token patterns
csrf_patterns = [
    # Meta tag
    {'element': 'meta', 'attrs': {'name': re.compile(r'csrf[-_]?token', re.I)}},
    # Input field
    {'element': 'input', 'attrs': {'name': re.compile(r'csrf[-_]?token', re.I)}},
    # ...more patterns...
]
```

## Testing the Enhanced HTTP Client

You can test the enhanced HTTP client using the provided test script:

```bash
python -m src.core.test_enhanced_client --url https://example.com --test waf
```

Available test modes:
- `waf`: Test WAF evasion techniques
- `session`: Test session management
- `form`: Test form submission with CSRF token handling

## Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `waf_evasion` | Enable WAF evasion techniques | `False` |
| `rotate_user_agent` | Rotate user agents | `False` |
| `maintain_session` | Maintain session cookies | `True` |
| `handle_csrf` | Automatically handle CSRF tokens | `True` |
| `rate_limit_min` | Minimum delay between requests | `0.5` seconds |
| `rate_limit_max` | Maximum delay between requests | `2.0` seconds |

## Advanced Usage

### Custom WAF Evasion

For specific WAFs, you can customize the evasion techniques:

```python
if detected_waf == "Cloudflare":
    # Cloudflare-specific evasion
    evasion_params['headers'] = {
        'CF-IPCountry': random.choice(['US', 'GB', 'CA', 'AU', 'DE', 'FR']),
        'Accept-Language': 'en-US,en;q=0.9',
        'Referer': url
    }
```

### Saving and Loading Cookies

The client provides methods to save and load cookies:

```python
# Save cookies to a file
client.save_cookies('cookies.json')

# Load cookies from a file
client.load_cookies('cookies.json')
```

## Integration with Scanners

The enhanced HTTP client is automatically integrated with all vulnerability scanners when enabled:

```python
scanners = {
    'xss': XSSScanner(http_client),
    'sqli': SQLiScanner(http_client),
    'ssrf': SSRFScanner(http_client)
}
```

## Performance Considerations

- WAF evasion techniques may slow down scanning due to additional delays and processing
- Session management requires additional memory to store cookies and CSRF tokens
- For maximum speed, disable these features when scanning trusted environments

## Troubleshooting

### 403 Forbidden Responses

If you're still getting 403 Forbidden responses:

1. Enable WAF evasion and rotating user agents
2. Try using a different proxy server
3. Increase the delay between requests
4. Check if the target site has IP-based blocking

### Session Management Issues

If session management isn't working correctly:

1. Verify that cookies are being properly stored (check client.get_cookies())
2. Ensure the site uses standard cookie-based sessions
3. Try manually specifying a session cookie if needed
