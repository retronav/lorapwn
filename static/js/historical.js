// Historical Data Page JavaScript
let currentPage = 1;
let totalPages = 1;
let currentFilters = {};
let isTableView = true;
let charts = {};
let importJobsPollingInterval = null;
let validatedCredentials = false;

// Initialize the page
document.addEventListener('DOMContentLoaded', function() {
    console.log('🚀 DOM Content Loaded - Starting initialization...');

    // Add a simple test to verify DOM elements exist
    console.log('Testing button existence:');
    console.log('- validate-credentials:', !!document.getElementById('validate-credentials'));
    console.log('- start-import:', !!document.getElementById('start-import'));
    console.log('- toggle-advanced:', !!document.getElementById('toggle-advanced'));
    console.log('- import-presets:', !!document.getElementById('import-presets'));
    console.log('- refresh-jobs:', !!document.getElementById('refresh-jobs'));

    initializePage();
    setupEventListeners();
    setupImportEventListeners(); // Add import event listeners
    loadDeviceList();
    setDefaultDateRange();
    loadDatePresets(); // Load quick date presets
    loadImportJobs(); // Load existing import jobs

    console.log('✅ Initialization complete!');
});

function initializePage() {
    // Initialize charts
    initializeCharts();

    // Load initial data
    applyFilters();
}

function setupEventListeners() {
    // Filter controls
    document.getElementById('apply-filters').addEventListener('click', applyFilters);
    document.getElementById('reset-filters').addEventListener('click', resetFilters);
    document.getElementById('export-data').addEventListener('click', exportData);

    // View toggle
    document.getElementById('toggle-view').addEventListener('click', toggleView);

    // Pagination
    document.getElementById('prev-page').addEventListener('click', () => changePage(-1));
    document.getElementById('next-page').addEventListener('click', () => changePage(1));

    // Modal controls
    document.getElementById('close-modal').addEventListener('click', closeModal);

    // Close modal when clicking outside
    document.getElementById('packet-modal').addEventListener('click', function(e) {
        if (e.target === this) {
            closeModal();
        }
    });
}

function setDefaultDateRange() {
    const now = new Date();
    const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

    // Format dates for datetime-local input
    document.getElementById('date-to').value = formatDateForInput(now);
    document.getElementById('date-from').value = formatDateForInput(oneDayAgo);
}

function formatDateForInput(date) {
    return date.toISOString().slice(0, 16);
}

async function loadDeviceList() {
    try {
        const response = await fetch('/api/devices');
        if (response.ok) {
            const devices = await response.json();
            const deviceSelect = document.getElementById('device-filter');

            // Clear existing options except "All Devices"
            deviceSelect.innerHTML = '<option value="">All Devices</option>';

            devices.forEach(device => {
                const option = document.createElement('option');
                option.value = device.device_id;
                option.textContent = device.device_id;
                deviceSelect.appendChild(option);
            });
        }
    } catch (error) {
        console.error('Failed to load device list:', error);
        showNotification('⚠️ Failed to load device list', 'warning');
    }
}

async function applyFilters() {
    showLoading(true);

    // Collect filter values
    currentFilters = {
        date_from: document.getElementById('date-from').value,
        date_to: document.getElementById('date-to').value,
        device_id: document.getElementById('device-filter').value,
        severity: document.getElementById('severity-filter').value,
        limit: parseInt(document.getElementById('limit-filter').value),
        page: currentPage
    };

    try {
        const queryParams = new URLSearchParams();
        Object.keys(currentFilters).forEach(key => {
            if (currentFilters[key]) {
                queryParams.append(key, currentFilters[key]);
            }
        });

        const [dataResponse, statsResponse] = await Promise.all([
            fetch(`/api/historical/packets?${queryParams}`),
            fetch(`/api/historical/stats?${queryParams}`)
        ]);

        if (dataResponse.ok && statsResponse.ok) {
            const data = await dataResponse.json();
            const stats = await statsResponse.json();

            updateSummaryStats(stats);
            updateDataDisplay(data.packets);
            updatePagination(data.total_pages, data.current_page);
            updateCharts(stats);

            showNotification('📊 Data loaded successfully', 'success');
        } else {
            throw new Error('Failed to fetch historical data');
        }
    } catch (error) {
        console.error('Error loading historical data:', error);
        showNotification('❌ Failed to load historical data', 'error');
    } finally {
        showLoading(false);
    }
}

function resetFilters() {
    document.getElementById('date-from').value = '';
    document.getElementById('date-to').value = '';
    document.getElementById('device-filter').value = '';
    document.getElementById('severity-filter').value = '';
    document.getElementById('limit-filter').value = '100';

    setDefaultDateRange();
    currentPage = 1;
    applyFilters();
}

function updateSummaryStats(stats) {
    document.getElementById('historical-packets').textContent = stats.total_packets || 0;
    document.getElementById('historical-findings').textContent = stats.total_findings || 0;
    document.getElementById('historical-devices').textContent = stats.unique_devices || 0;
    document.getElementById('historical-critical').textContent = stats.critical_findings || 0;
}

function updateDataDisplay(packets) {
    if (isTableView) {
        updateTableView(packets);
    } else {
        updateCardView(packets);
    }
}

function updateTableView(packets) {
    const tbody = document.getElementById('historical-table-body');

    if (packets.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="no-data">No packets found for the selected filters</td></tr>';
        return;
    }

    tbody.innerHTML = packets.map(packet => {
        const deviceId = packet.message.end_device_ids?.device_id || 'Unknown';
        const timestamp = new Date(packet.processed_at).toLocaleString();
        const fcnt = packet.message.uplink_message?.f_cnt || 'N/A';
        const rssi = packet.message.uplink_message?.rx_metadata?.[0]?.rssi || 'N/A';
        const findingsCount = packet.findings.length;

        // Get highest severity
        const severities = packet.findings.map(f => f.severity.toLowerCase());
        const highestSeverity = getHighestSeverity(severities);

        return `
            <tr>
                <td>${timestamp}</td>
                <td>${deviceId}</td>
                <td>${fcnt}</td>
                <td>${rssi} dBm</td>
                <td>${findingsCount}</td>
                <td><span class="severity-badge severity-${highestSeverity}">${highestSeverity || 'none'}</span></td>
                <td>
                    <button class="btn action-btn" onclick="viewPacketDetails('${packet.id}')">View</button>
                    <button class="btn btn-secondary action-btn" onclick="exportPacket('${packet.id}')">Export</button>
                </td>
            </tr>
        `;
    }).join('');
}

function updateCardView(packets) {
    const cardContainer = document.getElementById('card-view');

    if (packets.length === 0) {
        cardContainer.innerHTML = '<p class="no-data">No packets found for the selected filters</p>';
        return;
    }

    cardContainer.innerHTML = packets.map(packet => {
        const deviceId = packet.message.end_device_ids?.device_id || 'Unknown';
        const timestamp = new Date(packet.processed_at).toLocaleString();
        const fcnt = packet.message.uplink_message?.f_cnt || 'N/A';
        const fport = packet.message.uplink_message?.f_port || 'N/A';
        const rssi = packet.message.uplink_message?.rx_metadata?.[0]?.rssi || 'N/A';

        const findingsHtml = packet.findings.map(finding =>
            `<div class="finding-item ${finding.severity.toLowerCase()}">
                <strong>${finding.check}</strong> (${finding.severity}): ${finding.details}
            </div>`
        ).join('');

        return `
            <div class="packet-card">
                <div class="packet-header">
                    <strong>Device:</strong> ${deviceId} |
                    <strong>Time:</strong> ${timestamp} |
                    <strong>FCnt:</strong> ${fcnt} |
                    <strong>RSSI:</strong> ${rssi} dBm
                </div>
                <div class="packet-body">
                    <div class="findings-list">
                        <h4>Security Findings (${packet.findings.length}):</h4>
                        ${packet.findings.length > 0 ? findingsHtml : '<div class="finding-item info">✅ No security issues detected</div>'}
                    </div>
                    <div style="margin-top: 15px;">
                        <button class="btn action-btn" onclick="viewPacketDetails('${packet.id}')">View Details</button>
                        <button class="btn btn-secondary action-btn" onclick="exportPacket('${packet.id}')">Export</button>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

function getHighestSeverity(severities) {
    const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
    for (const severity of severityOrder) {
        if (severities.includes(severity)) {
            return severity;
        }
    }
    return 'info';
}

function toggleView() {
    isTableView = !isTableView;
    const tableView = document.getElementById('table-view');
    const cardView = document.getElementById('card-view');
    const toggleBtn = document.getElementById('toggle-view');

    if (isTableView) {
        tableView.style.display = 'block';
        cardView.style.display = 'none';
        toggleBtn.textContent = 'Switch to Card View';
    } else {
        tableView.style.display = 'none';
        cardView.style.display = 'block';
        toggleBtn.textContent = 'Switch to Table View';
    }

    // Re-apply current data to new view
    applyFilters();
}

function updatePagination(totalPgs, currentPg) {
    totalPages = totalPgs;
    currentPage = currentPg;

    const paginationContainer = document.getElementById('pagination-container');
    const pageInfo = document.getElementById('page-info');
    const prevBtn = document.getElementById('prev-page');
    const nextBtn = document.getElementById('next-page');

    if (totalPages > 1) {
        paginationContainer.style.display = 'flex';
        pageInfo.textContent = `Page ${currentPage} of ${totalPages}`;
        prevBtn.disabled = currentPage <= 1;
        nextBtn.disabled = currentPage >= totalPages;
    } else {
        paginationContainer.style.display = 'none';
    }
}

function changePage(direction) {
    const newPage = currentPage + direction;
    if (newPage >= 1 && newPage <= totalPages) {
        currentPage = newPage;
        applyFilters();
    }
}

async function viewPacketDetails(packetId) {
    try {
        const response = await fetch(`/api/historical/packet/${packetId}`);
        if (response.ok) {
            const packet = await response.json();
            showPacketModal(packet);
        } else {
            throw new Error('Failed to fetch packet details');
        }
    } catch (error) {
        console.error('Error loading packet details:', error);
        showNotification('❌ Failed to load packet details', 'error');
    }
}

function showPacketModal(packet) {
    const modal = document.getElementById('packet-modal');
    const modalBody = document.getElementById('packet-details');

    const deviceId = packet.message.end_device_ids?.device_id || 'Unknown';
    const timestamp = new Date(packet.processed_at).toLocaleString();
    const uplinkMessage = packet.message.uplink_message || {};

    modalBody.innerHTML = `
        <div class="packet-detail-grid">
            <h4>📱 Device Information</h4>
            <div class="detail-section">
                <p><strong>Device ID:</strong> ${deviceId}</p>
                <p><strong>Timestamp:</strong> ${timestamp}</p>
                <p><strong>Frame Counter:</strong> ${uplinkMessage.f_cnt || 'N/A'}</p>
                <p><strong>Frame Port:</strong> ${uplinkMessage.f_port || 'N/A'}</p>
                <p><strong>Frequency:</strong> ${uplinkMessage.settings?.frequency || 'N/A'} Hz</p>
                <p><strong>Data Rate:</strong> ${uplinkMessage.settings?.data_rate?.lora?.spreading_factor || 'N/A'}</p>
            </div>

            <h4>📡 Radio Information</h4>
            <div class="detail-section">
                ${uplinkMessage.rx_metadata ? uplinkMessage.rx_metadata.map(rx => `
                    <div class="rx-metadata">
                        <p><strong>Gateway:</strong> ${rx.gateway_ids?.gateway_id || 'Unknown'}</p>
                        <p><strong>RSSI:</strong> ${rx.rssi || 'N/A'} dBm</p>
                        <p><strong>SNR:</strong> ${rx.snr || 'N/A'} dB</p>
                        <p><strong>Channel:</strong> ${rx.channel_index || 'N/A'}</p>
                    </div>
                `).join('') : '<p>No radio metadata available</p>'}
            </div>

            <h4>📦 Payload Information</h4>
            <div class="detail-section">
                <p><strong>Raw Payload:</strong> <code>${uplinkMessage.frm_payload || 'None'}</code></p>
                <p><strong>Decoded Payload:</strong></p>
                <pre class="payload-json">${JSON.stringify(uplinkMessage.decoded_payload || {}, null, 2)}</pre>
            </div>

            <h4>🔍 Security Findings</h4>
            <div class="detail-section">
                ${packet.findings.length > 0 ? packet.findings.map(finding => `
                    <div class="finding-item ${finding.severity.toLowerCase()}">
                        <strong>${finding.check}</strong> (${finding.severity})
                        <p>${finding.details}</p>
                        ${finding.recommendation ? `<p><em>💡 ${finding.recommendation}</em></p>` : ''}
                    </div>
                `).join('') : '<p class="finding-item info">✅ No security issues detected</p>'}
            </div>

            <h4>🔧 Raw Message Data</h4>
            <div class="detail-section">
                <pre class="payload-json">${JSON.stringify(packet.message, null, 2)}</pre>
            </div>
        </div>
    `;

    modal.style.display = 'flex';
}

function closeModal() {
    document.getElementById('packet-modal').style.display = 'none';
}

async function exportPacket(packetId) {
    try {
        const response = await fetch(`/api/historical/packet/${packetId}/export`);
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `packet_${packetId}_${new Date().toISOString().slice(0, 10)}.json`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            showNotification('📁 Packet exported successfully', 'success');
        } else {
            throw new Error('Failed to export packet');
        }
    } catch (error) {
        console.error('Error exporting packet:', error);
        showNotification('❌ Failed to export packet', 'error');
    }
}

async function exportData() {
    try {
        const queryParams = new URLSearchParams();
        Object.keys(currentFilters).forEach(key => {
            if (currentFilters[key] && key !== 'page') {
                queryParams.append(key, currentFilters[key]);
            }
        });

        const response = await fetch(`/api/historical/export?${queryParams}`);
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `historical_data_${new Date().toISOString().slice(0, 10)}.csv`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            showNotification('📁 Data exported successfully', 'success');
        } else {
            throw new Error('Failed to export data');
        }
    } catch (error) {
        console.error('Error exporting data:', error);
        showNotification('❌ Failed to export data', 'error');
    }
}

function initializeCharts() {
    // Timeline Chart
    const timelineCtx = document.getElementById('timelineChart').getContext('2d');
    charts.timeline = new Chart(timelineCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Packets per Hour',
                data: [],
                borderColor: '#007bff',
                backgroundColor: 'rgba(0,123,255,0.1)',
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                x: {
                    display: true,
                    title: {
                        display: true,
                        text: 'Time'
                    }
                },
                y: {
                    display: true,
                    title: {
                        display: true,
                        text: 'Packet Count'
                    }
                }
            }
        }
    });

    // Severity Chart
    const severityCtx = document.getElementById('severityChart').getContext('2d');
    charts.severity = new Chart(severityCtx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
            datasets: [{
                data: [0, 0, 0, 0, 0],
                backgroundColor: [
                    '#dc3545',
                    '#ffc107',
                    '#fd7e14',
                    '#28a745',
                    '#17a2b8'
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        }
    });

    // Device Chart
    const deviceCtx = document.getElementById('deviceChart').getContext('2d');
    charts.device = new Chart(deviceCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Packets',
                data: [],
                backgroundColor: '#007bff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                x: {
                    display: true,
                    title: {
                        display: true,
                        text: 'Device ID'
                    }
                },
                y: {
                    display: true,
                    title: {
                        display: true,
                        text: 'Packet Count'
                    }
                }
            }
        }
    });
}

function updateCharts(stats) {
    // Update timeline chart
    if (stats.timeline) {
        charts.timeline.data.labels = stats.timeline.labels;
        charts.timeline.data.datasets[0].data = stats.timeline.data;
        charts.timeline.update();
    }

    // Update severity chart
    if (stats.severity_distribution) {
        charts.severity.data.datasets[0].data = [
            stats.severity_distribution.critical || 0,
            stats.severity_distribution.high || 0,
            stats.severity_distribution.medium || 0,
            stats.severity_distribution.low || 0,
            stats.severity_distribution.info || 0
        ];
        charts.severity.update();
    }

    // Update device chart
    if (stats.device_activity) {
        charts.device.data.labels = stats.device_activity.map(d => d.device_id);
        charts.device.data.datasets[0].data = stats.device_activity.map(d => d.packet_count);
        charts.device.update();
    }

    // Update top findings
    if (stats.top_findings) {
        updateTopFindings(stats.top_findings);
    }
}

function updateTopFindings(topFindings) {
    const container = document.getElementById('top-findings');

    if (topFindings.length === 0) {
        container.innerHTML = '<p class="no-data">No findings data available</p>';
        return;
    }

    container.innerHTML = topFindings.map(finding =>
        `<div class="top-finding">
            <span class="finding-name">${finding.check}</span>
            <span class="finding-count">${finding.count}</span>
        </div>`
    ).join('');
}

function showLoading(show) {
    const indicator = document.getElementById('loading-indicator');
    indicator.style.display = show ? 'inline' : 'none';
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

// Import Jobs Section

function setupImportEventListeners() {
    console.log('Setting up import event listeners...');

    // Import form controls
    const validateBtn = document.getElementById('validate-files');
    const previewBtn = document.getElementById('preview-files');
    const startBtn = document.getElementById('start-import');
    const toggleBtn = document.getElementById('toggle-examples');
    const refreshBtn = document.getElementById('refresh-jobs');

    if (validateBtn) {
        validateBtn.addEventListener('click', validateImportFiles);
        console.log('✅ Validate files button listener added');
    } else {
        console.error('❌ Validate files button not found');
    }

    if (previewBtn) {
        previewBtn.addEventListener('click', previewImportFiles);
        console.log('✅ Preview files button listener added');
    } else {
        console.error('❌ Preview files button not found');
    }

    if (startBtn) {
        startBtn.addEventListener('click', startFileImport);
        console.log('✅ Start import button listener added');
    } else {
        console.error('❌ Start import button not found');
    }

    if (toggleBtn) {
        toggleBtn.addEventListener('click', toggleExamples);
        console.log('✅ Toggle examples button listener added');
    } else {
        console.error('❌ Toggle examples button not found');
    }

    if (refreshBtn) {
        refreshBtn.addEventListener('click', loadImportJobs);
        console.log('✅ Refresh jobs button listener added');
    } else {
        console.error('❌ Refresh jobs button not found');
    }
}

function toggleExamples() {
    const content = document.getElementById('examples-content');
    const button = document.getElementById('toggle-examples');

    if (content.style.display === 'none') {
        content.style.display = 'block';
        button.textContent = '📖 Hide Examples';
    } else {
        content.style.display = 'none';
        button.textContent = '📖 File Format Examples';
    }
}

async function validateImportFiles() {
    const filePaths = document.getElementById('import-file-paths').value.trim();

    if (!filePaths) {
        showValidationStatus('Please enter at least one file path', 'error');
        return;
    }

    const filePathsArray = filePaths.split('\n').map(path => path.trim()).filter(path => path);

    showValidationStatus('Validating files...', 'info');

    try {
        const response = await fetch('/api/import/validate-credentials', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                application_id: 'json-import', // Placeholder
                access_key: 'not-used',       // Placeholder
                cluster: 'not-used',          // Placeholder
                duration: '1d',               // Placeholder
                device_ids: filePathsArray    // Pass file paths in device_ids field
            })
        });

        const result = await response.json();

        if (result.valid) {
            validatedCredentials = true;
            document.getElementById('start-import').disabled = false;

            const message = result.device_count
                ? `✅ Valid files! Found ${result.device_count} devices from preview.`
                : '✅ Valid files!';

            showValidationStatus(message, 'success');

            // Show available devices if provided
            if (result.available_devices && result.available_devices.length > 0) {
                showAvailableDevices(result.available_devices);
            }
        } else {
            validatedCredentials = false;
            document.getElementById('start-import').disabled = true;
            showValidationStatus(`❌ ${result.message}`, 'error');
        }
    } catch (error) {
        console.error('Validation error:', error);
        validatedCredentials = false;
        document.getElementById('start-import').disabled = true;
        showValidationStatus('❌ File validation failed. Please check file paths and formats.', 'error');
    }
}

async function previewImportFiles() {
    const filePaths = document.getElementById('import-file-paths').value.trim();

    if (!filePaths) {
        showValidationStatus('Please enter at least one file path', 'error');
        return;
    }

    const filePathsArray = filePaths.split('\n').map(path => path.trim()).filter(path => path);

    try {
        // For preview, we'll use the same validation endpoint but show more details
        const response = await fetch('/api/import/validate-credentials', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                application_id: 'json-preview',
                access_key: 'not-used',
                cluster: 'not-used',
                duration: '1d',
                device_ids: filePathsArray
            })
        });

        const result = await response.json();

        if (result.valid) {
            // Show preview in modal or expand area
            showPreviewModal(result);
        } else {
            showValidationStatus(`❌ Preview failed: ${result.message}`, 'error');
        }
    } catch (error) {
        console.error('Preview error:', error);
        showValidationStatus('❌ Preview failed. Please check file paths.', 'error');
    }
}

function showPreviewModal(previewData) {
    const modal = document.getElementById('packet-modal');
    const modalBody = document.getElementById('packet-details');

    modalBody.innerHTML = `
        <div class="preview-content">
            <h4>📋 File Preview</h4>
            <div class="preview-stats">
                <p><strong>Status:</strong> ${previewData.valid ? '✅ Valid' : '❌ Invalid'}</p>
                <p><strong>Message:</strong> ${previewData.message}</p>
                ${previewData.device_count ? `<p><strong>Devices Found:</strong> ${previewData.device_count}</p>` : ''}
            </div>

            ${previewData.available_devices && previewData.available_devices.length > 0 ? `
                <div class="preview-devices">
                    <h5>📱 Devices in Files:</h5>
                    <div class="device-list">
                        ${previewData.available_devices.slice(0, 10).map(device =>
                            `<span class="device-tag">${device}</span>`
                        ).join('')}
                        ${previewData.available_devices.length > 10 ?
                            `<span class="device-tag">... and ${previewData.available_devices.length - 10} more</span>` : ''}
                    </div>
                </div>
            ` : ''}

            <div class="preview-note">
                <strong>📝 Note:</strong> This is a preview based on file validation.
                Actual import may process different numbers of messages depending on filters and file content.
            </div>
        </div>
    `;

    modal.style.display = 'flex';
}

async function startFileImport() {
    if (!validatedCredentials) {
        showNotification('❌ Please validate files first', 'error');
        return;
    }

    const filePaths = document.getElementById('import-file-paths').value.trim();
    const deviceFilter = document.getElementById('import-device-filter').value.trim();
    const batchSize = parseInt(document.getElementById('batch-size').value) || 500;

    if (!filePaths) {
        showNotification('❌ Please enter file paths', 'error');
        return;
    }

    const filePathsArray = filePaths.split('\n').map(path => path.trim()).filter(path => path);
    const deviceIds = deviceFilter ? deviceFilter.split(',').map(d => d.trim()).filter(d => d) : null;

    const importRequest = {
        application_id: 'json-import',
        access_key: 'not-used',
        cluster: 'not-used',
        duration: '1d',
        device_ids: filePathsArray, // Pass file paths
        batch_size: batchSize,
        rate_limit_delay_ms: 0 // Not needed for file import
    };

    try {
        const response = await fetch('/api/import/start', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(importRequest)
        });

        const result = await response.json();

        if (response.ok) {
            showNotification(`🚀 Import job started! Job ID: ${result.job_id}`, 'success');

            // Clear form
            document.getElementById('import-file-paths').value = '';
            document.getElementById('import-device-filter').value = '';
            document.getElementById('start-import').disabled = true;
            validatedCredentials = false;
            showValidationStatus('', 'info');

            // Refresh jobs list
            await loadImportJobs();

            // Start polling for job updates
            startImportJobsPolling();

        } else {
            throw new Error(result.message || 'Failed to start import');
        }
    } catch (error) {
        console.error('Import start error:', error);
        showNotification(`❌ Failed to start import: ${error.message}`, 'error');
    }
}

async function loadDatePresets() {
    try {
        const response = await fetch('/api/import/date-presets');
        if (response.ok) {
            const data = await response.json();
            // For JSON file import, we don't need date presets
            // but we can keep this function for future compatibility
            console.log('Date presets loaded (not used in JSON import):', data);
        }
    } catch (error) {
        console.error('Failed to load date presets:', error);
    }
}

function handlePresetSelection() {
    // Not needed for JSON file import, but keeping for compatibility
    console.log('Preset selection not applicable for JSON file import');
}

function toggleAdvancedOptions() {
    // Not needed for JSON file import, but keeping for compatibility
    console.log('Advanced options not applicable for JSON file import');
}

async function validateImportCredentials() {
    // This function is replaced by validateImportFiles
    console.log('validateImportCredentials called - redirecting to validateImportFiles');
    await validateImportFiles();
}

function showValidationStatus(message, type) {
    const statusDiv = document.getElementById('validation-status');
    if (!statusDiv) return;

    statusDiv.className = `validation-status ${type}`;
    statusDiv.textContent = message;

    // Show for 5 seconds if it's a success or error message
    if (type === 'success' || type === 'error') {
        setTimeout(() => {
            if (statusDiv.textContent === message) {
                statusDiv.textContent = '';
                statusDiv.className = 'validation-status';
            }
        }, 5000);
    }
}

function showAvailableDevices(devices) {
    const statusDiv = document.getElementById('validation-status');
    if (!statusDiv || !devices || devices.length === 0) return;

    const deviceList = devices.slice(0, 5).join(', ');
    const moreText = devices.length > 5 ? ` and ${devices.length - 5} more` : '';

    const currentMessage = statusDiv.textContent;
    statusDiv.innerHTML = `
        ${currentMessage}<br>
        <small>📱 Devices found: ${deviceList}${moreText}</small>
    `;
}

async function startHistoricalImport() {
    // This function is replaced by startFileImport
    console.log('startHistoricalImport called - redirecting to startFileImport');
    await startFileImport();
}

async function loadImportJobs() {
    try {
        const response = await fetch('/api/import/jobs');
        if (response.ok) {
            const jobs = await response.json();
            updateImportJobsDisplay(jobs);

            // If there are active jobs, start polling
            const hasActiveJobs = jobs.some(job =>
                job.progress && (job.progress.status === 'Pending' || job.progress.status === 'InProgress')
            );

            if (hasActiveJobs) {
                startImportJobsPolling();
            } else {
                stopImportJobsPolling();
            }
        }
    } catch (error) {
        console.error('Error loading import jobs:', error);
        showNotification('⚠️ Failed to load import jobs', 'warning');
    }
}

function updateImportJobsDisplay(jobs) {
    const container = document.getElementById('jobs-container');

    if (jobs.length === 0) {
        container.innerHTML = '<p class="no-jobs">No import jobs running</p>';
        return;
    }

    container.innerHTML = jobs.map(job => {
        const progress = job.progress || job[1]; // Handle both formats
        const jobId = job.job_id || job[0]; // Handle both formats

        if (!progress) return '';

        const progressPercent = progress.total_messages > 0
            ? Math.round((progress.processed_messages / progress.total_messages) * 100)
            : 0;

        const statusClass = progress.status.toLowerCase().replace(/([A-Z])/g, '-$1').toLowerCase();

        return `
            <div class="job-card">
                <div class="job-header">
                    <span class="job-id">Job: ${jobId}</span>
                    <span class="job-status ${statusClass}">${progress.status}</span>
                </div>
                <div class="job-body">
                    <div class="job-info">
                        <div class="job-info-item">
                            <span class="job-info-label">Total Messages</span>
                            <span class="job-info-value">${progress.total_messages}</span>
                        </div>
                        <div class="job-info-item">
                            <span class="job-info-label">Processed</span>
                            <span class="job-info-value">${progress.processed_messages}</span>
                        </div>
                        <div class="job-info-item">
                            <span class="job-info-label">Imported</span>
                            <span class="job-info-value">${progress.imported_messages}</span>
                        </div>
                        <div class="job-info-item">
                            <span class="job-info-label">Failed</span>
                            <span class="job-info-value">${progress.failed_messages}</span>
                        </div>
                        ${progress.current_file ? `
                        <div class="job-info-item">
                            <span class="job-info-label">Current File</span>
                            <span class="job-info-value">${progress.current_file}</span>
                        </div>
                        ` : ''}
                    </div>

                    ${progress.status === 'InProgress' ? `
                        <div class="progress-bar-container">
                            <div class="progress-bar">
                                <div class="progress-fill" style="width: ${progressPercent}%"></div>
                            </div>
                            <div class="progress-text">${progressPercent}% complete</div>
                        </div>
                    ` : ''}

                    <div class="job-actions">
                        ${progress.status === 'InProgress' ? `
                            <button class="btn btn-danger" onclick="cancelImportJob('${jobId}')">
                                Cancel Job
                            </button>
                        ` : ''}
                        <button class="btn btn-info" onclick="viewJobDetails('${jobId}')">
                            View Details
                        </button>
                    </div>

                    ${progress.error_messages && progress.error_messages.length > 0 ? `
                        <div class="error-messages">
                            <strong>Errors:</strong>
                            ${progress.error_messages.slice(0, 3).map(error =>
                                `<div class="error-message">${error}</div>`
                            ).join('')}
                            ${progress.error_messages.length > 3 ?
                                `<div class="error-message">... and ${progress.error_messages.length - 3} more errors</div>`
                                : ''}
                        </div>
                    ` : ''}
                </div>
            </div>
        `;
    }).join('');
}

async function cancelImportJob(jobId) {
    if (!confirm('Are you sure you want to cancel this import job?')) {
        return;
    }

    try {
        const response = await fetch(`/api/import/cancel/${jobId}`, {
            method: 'POST'
        });

        if (response.ok) {
            showNotification('🛑 Import job cancelled', 'success');
            await loadImportJobs();
        } else {
            throw new Error('Failed to cancel job');
        }
    } catch (error) {
        console.error('Error cancelling job:', error);
        showNotification('❌ Failed to cancel job', 'error');
    }
}

async function viewJobDetails(jobId) {
    try {
        const response = await fetch(`/api/import/progress/${jobId}`);
        if (response.ok) {
            const jobData = await response.json();
            showJobDetailsModal(jobData);
        } else {
            throw new Error('Failed to fetch job details');
        }
    } catch (error) {
        console.error('Error loading job details:', error);
        showNotification('❌ Failed to load job details', 'error');
    }
}

function showJobDetailsModal(jobData) {
    const modal = document.getElementById('packet-modal');
    const modalBody = document.getElementById('packet-details');

    const progress = jobData.progress;
    const startTime = new Date(progress.start_time).toLocaleString();
    const estimatedCompletion = progress.estimated_completion
        ? new Date(progress.estimated_completion).toLocaleString()
        : 'Unknown';

    modalBody.innerHTML = `
        <div class="job-details">
            <h4>📊 Import Job Details</h4>
            <div class="detail-section">
                <p><strong>Job ID:</strong> ${jobData.job_id}</p>
                <p><strong>Status:</strong> <span class="job-status ${progress.status.toLowerCase()}">${progress.status}</span></p>
                <p><strong>Started:</strong> ${startTime}</p>
                <p><strong>Estimated Completion:</strong> ${estimatedCompletion}</p>
                ${progress.current_file ? `<p><strong>Current File:</strong> ${progress.current_file}</p>` : ''}
            </div>

            <h4>📈 Progress Statistics</h4>
            <div class="detail-section">
                <p><strong>Total Messages:</strong> ${progress.total_messages}</p>
                <p><strong>Processed:</strong> ${progress.processed_messages}</p>
                <p><strong>Successfully Imported:</strong> ${progress.imported_messages}</p>
                <p><strong>Failed:</strong> ${progress.failed_messages}</p>
            </div>

            ${progress.error_messages && progress.error_messages.length > 0 ? `
                <h4>❌ Error Messages</h4>
                <div class="detail-section">
                    <div class="error-messages" style="max-height: 200px; overflow-y: auto;">
                        ${progress.error_messages.map(error =>
                            `<div class="error-message">${error}</div>`
                        ).join('')}
                    </div>
                </div>
            ` : ''}

            <h4>🔧 Raw Job Data</h4>
            <div class="detail-section">
                <pre class="payload-json">${JSON.stringify(progress, null, 2)}</pre>
            </div>
        </div>
    `;

    modal.style.display = 'flex';
}

function startImportJobsPolling() {
    if (importJobsPollingInterval) {
        clearInterval(importJobsPollingInterval);
    }

    importJobsPollingInterval = setInterval(async () => {
        await loadImportJobs();
    }, 3000); // Poll every 3 seconds
}

function stopImportJobsPolling() {
    if (importJobsPollingInterval) {
        clearInterval(importJobsPollingInterval);
        importJobsPollingInterval = null;
    }
}
