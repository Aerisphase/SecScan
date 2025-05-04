# JavaScript Rendering Setup Guide

This guide explains how to set up and use the JavaScript rendering functionality in SecScan.

## Prerequisites

Before using the JavaScript rendering functionality, you need to install the required dependencies:

```bash
# Install Python dependencies
pip install -r requirements.txt

# Install Playwright browsers
python -m playwright install chromium
```

## Configuration

JavaScript rendering can be enabled through:

1. **Command Line Interface**:
   ```bash
   python -m src.core.scanner --target https://example.com --js-enabled
   ```

2. **Web Interface**:
   - Open the SecScan web interface
   - Check the "Enable JavaScript rendering" option in the scan configuration form
   - Configure browser timeout and network idle settings if needed

## Advanced Configuration Options

The following options can be configured for JavaScript rendering:

| Option | Description | Default |
|--------|-------------|---------|
| `js_enabled` | Enable JavaScript rendering | `false` |
| `browser_timeout` | Browser navigation timeout in milliseconds | `30000` (30 seconds) |
| `wait_for_idle` | Wait for network to be idle before processing page | `true` |

## Testing JavaScript Rendering

You can test the JavaScript rendering functionality using the provided test script:

```bash
python -m src.core.test_js_crawler
```

This script will crawl a sample website with JavaScript rendering enabled and display information about the discovered pages and forms.

## Troubleshooting

### Common Issues

1. **Browser Installation Failed**:
   - Ensure you have sufficient permissions to install browsers
   - Try running `python -m playwright install chromium` with administrator privileges

2. **JavaScript Rendering Timeout**:
   - Increase the `browser_timeout` value for slow websites
   - Disable `wait_for_idle` if the network never becomes completely idle

3. **403 Forbidden Errors**:
   - Try using a different user agent
   - Some websites may block automated browsers

### Browser Cache

Playwright browser data is stored in the `.playwright-browsers/` directory. If you encounter issues with browser installation or execution, you can try removing this directory and reinstalling the browsers:

```bash
rm -rf .playwright-browsers/
python -m playwright install chromium
```

## Performance Considerations

JavaScript rendering requires more resources than standard crawling:

- **Memory Usage**: Each browser instance requires approximately 100-200MB of RAM
- **CPU Usage**: JavaScript execution can be CPU-intensive
- **Scan Time**: Scans with JavaScript rendering enabled will take longer to complete

For large-scale scans, consider limiting the maximum number of pages to scan.
