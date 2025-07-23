// Historical Data Page JavaScript
let currentPage = 1;
let totalPages = 1;
let currentFilters = {};
let isTableView = true;
let charts = {};

// Initialize the page
document.addEventListener('DOMContentLoaded', function() {
    initializePage();
    setupEventListeners();
    loadDeviceList();
    setDefaultDateRange();
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
