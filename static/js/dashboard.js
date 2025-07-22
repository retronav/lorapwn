let isConnected = false;

// Load saved credentials from localStorage on page load
document.addEventListener('DOMContentLoaded', function() {
    loadSavedCredentials();
    checkConnectionStatus();
});

function saveCredentials() {
    const appId = document.getElementById('app-id').value;
    const accessKey = document.getElementById('access-key').value;
    const cluster = document.getElementById('cluster').value;

    if (appId && accessKey && cluster) {
        const credentials = {
            app_id: appId,
            access_key: accessKey,
            cluster: cluster,
            saved_at: new Date().toISOString()
        };
        localStorage.setItem('ttn_credentials', JSON.stringify(credentials));
        console.log('✅ Credentials saved to localStorage');
    }
}

function loadSavedCredentials() {
    try {
        const savedCredentials = localStorage.getItem('ttn_credentials');
        if (savedCredentials) {
            const credentials = JSON.parse(savedCredentials);

            // Check if credentials are not too old (optional: expire after 30 days)
            const savedDate = new Date(credentials.saved_at);
            const daysDiff = (new Date() - savedDate) / (1000 * 60 * 60 * 24);

            if (daysDiff < 30) {
                document.getElementById('app-id').value = credentials.app_id || '';
                document.getElementById('access-key').value = credentials.access_key || '';
                document.getElementById('cluster').value = credentials.cluster || 'eu1';
                console.log('✅ Credentials loaded from localStorage');

                // Show a subtle indication that credentials were loaded
                showNotification('📱 Saved credentials loaded', 'info');
            } else {
                // Clear old credentials
                localStorage.removeItem('ttn_credentials');
                console.log('🧹 Expired credentials removed');
            }
        }
    } catch (error) {
        console.error('❌ Error loading credentials from localStorage:', error);
        localStorage.removeItem('ttn_credentials');
    }
}

function clearSavedCredentials() {
    localStorage.removeItem('ttn_credentials');
    document.getElementById('app-id').value = '';
    document.getElementById('access-key').value = '';
    document.getElementById('cluster').value = 'eu1';
    showNotification('🗑️ Saved credentials cleared', 'info');
}

async function checkConnectionStatus() {
    try {
        const response = await fetch('/api/statistics');
        if (response.ok) {
            const stats = await response.json();
            if (stats.connection_status) {
                isConnected = true;
                updateConnectionUI();
                startPolling();
                showNotification('🔗 Reconnected to existing session', 'success');
            }
        }
    } catch (error) {
        console.log('No existing connection found');
    }
}

function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 12px 20px;
        border-radius: 6px;
        color: white;
        font-weight: bold;
        z-index: 1000;
        animation: slideIn 0.3s ease-out;
        max-width: 300px;
        word-wrap: break-word;
    `;

    // Set colors based on type
    switch (type) {
        case 'success':
            notification.style.backgroundColor = '#28a745';
            break;
        case 'error':
            notification.style.backgroundColor = '#dc3545';
            break;
        case 'warning':
            notification.style.backgroundColor = '#ffc107';
            notification.style.color = '#000';
            break;
        default:
            notification.style.backgroundColor = '#17a2b8';
    }

    notification.textContent = message;
    document.body.appendChild(notification);

    // Add CSS animation
    const style = document.createElement('style');
    style.textContent = `
        @keyframes slideIn {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
    `;
    document.head.appendChild(style);

    // Remove notification after 4 seconds
    setTimeout(() => {
        notification.style.animation = 'slideIn 0.3s ease-out reverse';
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 300);
    }, 4000);
}

// Event listeners
document.getElementById('connect-btn').addEventListener('click', async () => {
    const appId = document.getElementById('app-id').value;
    const accessKey = document.getElementById('access-key').value;
    const cluster = document.getElementById('cluster').value;

    if (!appId || !accessKey) {
        showNotification('⚠️ Please fill in Application ID and Access Key', 'warning');
        return;
    }

    // Show connecting state
    const connectBtn = document.getElementById('connect-btn');
    const originalText = connectBtn.textContent;
    connectBtn.textContent = 'Connecting...';
    connectBtn.disabled = true;

    try {
        const response = await fetch('/api/connect', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ app_id: appId, access_key: accessKey, cluster: cluster })
        });

        if (response.ok) {
            isConnected = true;
            updateConnectionUI();
            startPolling();
            saveCredentials(); // Save credentials on successful connection
            showNotification('🎉 Successfully connected to TTN!', 'success');
        } else {
            const errorText = await response.text();
            showNotification('❌ Failed to connect: ' + errorText, 'error');
        }
    } catch (error) {
        showNotification('❌ Connection error: ' + error.message, 'error');
    } finally {
        // Reset button state
        connectBtn.textContent = originalText;
        connectBtn.disabled = false;
    }
});

document.getElementById('disconnect-btn').addEventListener('click', async () => {
    try {
        await fetch('/api/disconnect', { method: 'POST' });
        isConnected = false;
        updateConnectionUI();
        stopPolling();
        showNotification('👋 Disconnected from TTN', 'info');
    } catch (error) {
        console.error('Disconnect error:', error);
        showNotification('⚠️ Disconnect error: ' + error.message, 'warning');
    }
});

document.getElementById('clear-credentials-btn').addEventListener('click', () => {
    clearSavedCredentials();
});

function updateConnectionUI() {
    const connectBtn = document.getElementById('connect-btn');
    const disconnectBtn = document.getElementById('disconnect-btn');
    const statusText = document.getElementById('status-text');
    const clearBtn = document.getElementById('clear-credentials-btn');

    if (isConnected) {
        connectBtn.style.display = 'none';
        disconnectBtn.style.display = 'inline-block';
        clearBtn.style.display = 'none';
        statusText.textContent = 'Connected';
        statusText.className = 'status-connected';
    } else {
        connectBtn.style.display = 'inline-block';
        disconnectBtn.style.display = 'none';
        clearBtn.style.display = 'inline-block';
        statusText.textContent = 'Disconnected';
        statusText.className = 'status-disconnected';
    }
}

let pollingInterval;

function startPolling() {
    pollingInterval = setInterval(async () => {
        try {
            const [statsResponse, packetsResponse] = await Promise.all([
                fetch('/api/statistics'),
                fetch('/api/packets?limit=10')
            ]);

            if (statsResponse.ok && packetsResponse.ok) {
                const stats = await statsResponse.json();
                const packets = await packetsResponse.json();

                updateStatistics(stats);
                updatePacketList(packets);
            }
        } catch (error) {
            console.error('Polling error:', error);
        }
    }, 3000);
}

function stopPolling() {
    if (pollingInterval) {
        clearInterval(pollingInterval);
    }
}

function updateStatistics(stats) {
    document.getElementById('total-packets').textContent = stats.total_packets || 0;
    document.getElementById('total-findings').textContent = stats.total_findings || 0;
    document.getElementById('unique-devices').textContent = stats.unique_devices || 0;
    document.getElementById('critical-findings').textContent = stats.severity_counts?.critical || 0;
}

function updatePacketList(packets) {
    const container = document.getElementById('packets-container');

    if (packets.length === 0) {
        container.innerHTML = '<p>No packets received yet...</p>';
        return;
    }

    container.innerHTML = packets.map(packet => {
        const deviceId = packet.message.end_device_ids?.device_id || 'Unknown';
        const timestamp = new Date(packet.processed_at).toLocaleString();
        const fcnt = packet.message.uplink_message?.f_cnt || 'N/A';
        const fport = packet.message.uplink_message?.f_port || 'N/A';

        // Extract payload information
        const frmPayload = packet.message.uplink_message?.frm_payload || null;
        const decodedPayload = packet.message.uplink_message?.decoded_payload || null;

        // Format payload display
        let payloadHtml = '<div class="payload-section">';

        if (frmPayload) {
            payloadHtml += `<div class="payload-item">
                <strong>Raw Payload (Hex):</strong>
                <code class="payload-hex">${frmPayload}</code>
            </div>`;

            // Convert hex to ASCII if possible
            try {
                const hexString = frmPayload.replace(/[^0-9A-Fa-f]/g, '');
                let ascii = '';
                for (let i = 0; i < hexString.length; i += 2) {
                    const byte = parseInt(hexString.substr(i, 2), 16);
                    ascii += (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';
                }
                if (ascii.replace(/\./g, '').length > 0) {
                    payloadHtml += `<div class="payload-item">
                        <strong>ASCII:</strong>
                        <code class="payload-ascii">${ascii}</code>
                    </div>`;
                }
            } catch (e) {
                // Ignore conversion errors
            }
        }

        if (decodedPayload && decodedPayload !== null) {
            payloadHtml += `<div class="payload-item">
                <strong>Decoded Payload:</strong>
                <pre class="payload-json">${JSON.stringify(decodedPayload, null, 2)}</pre>
            </div>`;
        } else if (frmPayload) {
            payloadHtml += `<div class="payload-item">
                <strong>Decoded Payload:</strong>
                <span class="payload-none">No decoder configured</span>
            </div>`;
        }

        payloadHtml += '</div>';

        const findingsHtml = packet.findings.map(finding =>
            `<div class="finding ${finding.severity.toLowerCase()}">
                <strong>${finding.check}</strong> (${finding.severity}): ${finding.details}
                ${finding.recommendation ? `<br><em>💡 ${finding.recommendation}</em>` : ''}
            </div>`
        ).join('');

        return `
            <div class="packet-card">
                <div class="packet-header">
                    <strong>Device:</strong> ${deviceId} |
                    <strong>FCnt:</strong> ${fcnt} |
                    <strong>FPort:</strong> ${fport} |
                    <strong>Time:</strong> ${timestamp} |
                    <strong>Findings:</strong> ${packet.findings.length}
                </div>
                <div class="packet-body">
                    ${payloadHtml}
                    <div class="findings-section">
                        <h4>Security Findings:</h4>
                        ${packet.findings.length > 0 ? findingsHtml : '<div class="finding low">✅ No security issues detected</div>'}
                    </div>
                </div>
            </div>
        `;
    }).join('');
}
