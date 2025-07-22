let charts = {};
let analysisData = null;

document.addEventListener('DOMContentLoaded', function() {
    loadAnalysis();

    document.getElementById('refresh-analysis').addEventListener('click', loadAnalysis);
    document.getElementById('trigger-analysis').addEventListener('click', triggerNewAnalysis);
});

async function loadAnalysis() {
    showLoading();
    try {
        const response = await fetch('/api/clustering-analysis');
        const data = await response.json();

        if (data.status === 'analysis_running') {
            setTimeout(loadAnalysis, 3000); // Retry in 3 seconds
            return;
        }

        analysisData = data;
        displayAnalysis(data);
        hideLoading();
        updateLastUpdated();
    } catch (error) {
        console.error('Error loading analysis:', error);
        hideLoading();
        showError('Failed to load clustering analysis');
    }
}

async function triggerNewAnalysis() {
    showLoading();
    try {
        const response = await fetch('/api/trigger-clustering', { method: 'POST' });
        const result = await response.json();

        if (result.status === 'success') {
            setTimeout(loadAnalysis, 2000); // Load results after 2 seconds
        } else {
            hideLoading();
            showError(result.message || 'Failed to trigger analysis');
        }
    } catch (error) {
        console.error('Error triggering analysis:', error);
        hideLoading();
        showError('Failed to trigger clustering analysis');
    }
}

function displayAnalysis(data) {
    if (!data.insights) {
        showError('No analysis data available');
        return;
    }

    const insights = data.insights;

    // Update summary statistics
    document.getElementById('security-score').textContent = (insights.summary.security_score * 100).toFixed(1) + '%';
    document.getElementById('network-score').textContent = (insights.summary.network_health_score * 100).toFixed(1) + '%';
    document.getElementById('devices-count').textContent = insights.summary.total_devices || 0;

    const totalClusters = (data.device_clusters?.length || 0) +
                        (data.security_clusters?.length || 0) +
                        (data.network_clusters?.length || 0) +
                        (data.temporal_clusters?.length || 0);
    document.getElementById('clusters-count').textContent = totalClusters;

    // Display clusters
    displayDeviceClusters(data.device_clusters || []);
    displaySecurityClusters(data.security_clusters || [], insights.anomalies || []);
    displayNetworkClusters(data.network_clusters || []);
    displayTemporalClusters(data.temporal_clusters || []);
    displayRecommendations(insights.recommendations || []);
    displayTrends(insights.trends || []);

    // Create charts
    createCharts(data);
}

function displayDeviceClusters(clusters) {
    const container = document.getElementById('device-clusters');
    container.innerHTML = '';

    if (clusters.length === 0) {
        container.innerHTML = '<p style="color: #6c757d; font-style: italic;">No device clusters found</p>';
        return;
    }

    clusters.forEach(cluster => {
        const item = document.createElement('div');
        item.className = 'cluster-item';
        item.innerHTML = `
            <div class="cluster-title">${cluster.cluster_id}</div>
            <div class="cluster-details">
                <strong>Devices:</strong> ${cluster.devices.length}<br>
                <strong>Pattern:</strong> ${cluster.characteristics.activity_pattern}<br>
                <strong>Avg RSSI:</strong> ${cluster.characteristics.avg_rssi.toFixed(1)} dBm<br>
                <strong>Reliability:</strong> ${(cluster.characteristics.reliability_score * 100).toFixed(1)}%
            </div>
        `;
        container.appendChild(item);
    });
}

function displaySecurityClusters(clusters, anomalies) {
    const container = document.getElementById('security-clusters');
    container.innerHTML = '';

    // Display anomalies first
    const anomaliesContainer = document.getElementById('security-anomalies');
    anomaliesContainer.innerHTML = '';

    anomalies.forEach(anomaly => {
        const alert = document.createElement('div');
        alert.className = 'anomaly-alert';
        alert.innerHTML = `
            <strong>${anomaly.anomaly_type}</strong><br>
            ${anomaly.description}<br>
            <small>Confidence: ${(anomaly.confidence * 100).toFixed(1)}% | Affected: ${anomaly.affected_devices.length} devices</small>
        `;
        anomaliesContainer.appendChild(alert);
    });

    if (clusters.length === 0) {
        container.innerHTML = '<p style="color: #28a745; font-style: italic;">✅ No security threats detected</p>';
        return;
    }

    clusters.forEach(cluster => {
        const item = document.createElement('div');
        item.className = 'cluster-item security';
        const threatColor = {
            'Critical': '#dc3545',
            'Malicious': '#fd7e14',
            'Suspicious': '#ffc107',
            'Benign': '#28a745'
        }[cluster.threat_level] || '#6c757d';

        item.innerHTML = `
            <div class="cluster-title" style="color: ${threatColor}">${cluster.cluster_id}</div>
            <div class="cluster-details">
                <strong>Threat Level:</strong> ${cluster.threat_level}<br>
                <strong>Affected Devices:</strong> ${cluster.affected_devices.length}<br>
                <strong>Pattern:</strong> ${cluster.temporal_pattern}<br>
                <strong>Findings:</strong> ${cluster.finding_patterns.join(', ')}
            </div>
        `;
        container.appendChild(item);
    });
}

function displayNetworkClusters(clusters) {
    const container = document.getElementById('network-clusters');
    container.innerHTML = '';

    if (clusters.length === 0) {
        container.innerHTML = '<p style="color: #6c757d; font-style: italic;">No network clusters found</p>';
        return;
    }

    clusters.forEach(cluster => {
        const item = document.createElement('div');
        item.className = 'cluster-item network';
        item.innerHTML = `
            <div class="cluster-title">${cluster.cluster_id}</div>
            <div class="cluster-details">
                <strong>Quality Score:</strong> ${(cluster.quality_score * 100).toFixed(1)}%<br>
                <strong>RSSI Range:</strong> ${cluster.rssi_range[0]} to ${cluster.rssi_range[1]} dBm<br>
                <strong>Devices:</strong> ${cluster.affected_devices.length}<br>
                <strong>Packet Loss:</strong> ${(cluster.coverage_analysis.reliability_metrics.packet_loss_rate * 100).toFixed(2)}%
            </div>
        `;
        container.appendChild(item);
    });
}

function displayTemporalClusters(clusters) {
    const container = document.getElementById('temporal-clusters');
    container.innerHTML = '';

    if (clusters.length === 0) {
        container.innerHTML = '<p style="color: #6c757d; font-style: italic;">No temporal patterns found</p>';
        return;
    }

    clusters.forEach(cluster => {
        const item = document.createElement('div');
        item.className = 'cluster-item temporal';
        item.innerHTML = `
            <div class="cluster-title">${cluster.cluster_id}</div>
            <div class="cluster-details">
                <strong>Pattern:</strong> ${cluster.time_pattern}<br>
                <strong>Frequency:</strong> ${cluster.frequency.toFixed(3)} Hz<br>
                <strong>Activity Score:</strong> ${(cluster.activity_score * 100).toFixed(1)}%<br>
                <strong>Peak Hours:</strong> ${cluster.peak_hours.join(', ') || 'None'}
            </div>
        `;
        container.appendChild(item);
    });
}

function displayRecommendations(recommendations) {
    const container = document.getElementById('recommendations');
    container.innerHTML = '';

    if (recommendations.length === 0) {
        container.innerHTML = '<p style="color: #6c757d; font-style: italic;">No recommendations at this time</p>';
        return;
    }

    recommendations.forEach(rec => {
        const item = document.createElement('div');
        item.className = 'recommendation';
        item.innerHTML = `
            <strong>${rec.title}</strong><br>
            ${rec.description}<br>
            <small><strong>Priority:</strong> ${rec.priority} | <strong>Impact:</strong> ${rec.impact}</small>
        `;
        container.appendChild(item);
    });
}

function displayTrends(trends) {
    const container = document.getElementById('trends');
    container.innerHTML = '';

    if (trends.length === 0) {
        container.innerHTML = '<p style="color: #6c757d; font-style: italic;">No trends detected</p>';
        return;
    }

    trends.forEach(trend => {
        const item = document.createElement('div');
        item.className = 'trend-item';
        const directionClass = trend.direction.toLowerCase().includes('up') ? 'trend-up' :
                             trend.direction.toLowerCase().includes('down') ? 'trend-down' : 'trend-stable';

        item.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <strong>${trend.trend_type}</strong>
                <span class="trend-direction ${directionClass}">${trend.direction}</span>
            </div>
            <div style="margin-top: 5px; font-size: 0.9rem; color: #6c757d;">
                ${trend.description}
            </div>
        `;
        container.appendChild(item);
    });
}

function createCharts(data) {
    // Device Behavior Chart
    if (data.device_clusters && data.device_clusters.length > 0) {
        createDeviceBehaviorChart(data.device_clusters);
    }

    // Network Quality Chart
    if (data.network_clusters && data.network_clusters.length > 0) {
        createNetworkQualityChart(data.network_clusters);
    }

    // Temporal Chart
    if (data.temporal_clusters && data.temporal_clusters.length > 0) {
        createTemporalChart(data.temporal_clusters);
    }
}

function createDeviceBehaviorChart(clusters) {
    const ctx = document.getElementById('deviceBehaviorChart');
    if (!ctx) return;

    if (charts.deviceBehavior) {
        charts.deviceBehavior.destroy();
    }

    const labels = clusters.map(c => c.cluster_id);
    const sizes = clusters.map(c => c.size);
    const reliabilityScores = clusters.map(c => c.characteristics.reliability_score * 100);

    charts.deviceBehavior = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Cluster Size',
                data: sizes,
                backgroundColor: 'rgba(54, 162, 235, 0.6)',
                borderColor: 'rgba(54, 162, 235, 1)',
                borderWidth: 1,
                yAxisID: 'y'
            }, {
                label: 'Reliability (%)',
                data: reliabilityScores,
                type: 'line',
                borderColor: 'rgba(255, 99, 132, 1)',
                backgroundColor: 'rgba(255, 99, 132, 0.2)',
                yAxisID: 'y1'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: 'Device Behavior Clusters'
                }
            },
            scales: {
                y: {
                    type: 'linear',
                    display: true,
                    position: 'left',
                },
                y1: {
                    type: 'linear',
                    display: true,
                    position: 'right',
                    grid: {
                        drawOnChartArea: false,
                    },
                }
            }
        }
    });
}

function createNetworkQualityChart(clusters) {
    const ctx = document.getElementById('networkQualityChart');
    if (!ctx) return;

    if (charts.networkQuality) {
        charts.networkQuality.destroy();
    }

    const labels = clusters.map(c => c.cluster_id);
    const qualityScores = clusters.map(c => c.quality_score * 100);

    charts.networkQuality = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: qualityScores,
                backgroundColor: [
                    'rgba(40, 167, 69, 0.6)',   // Green for good quality
                    'rgba(255, 193, 7, 0.6)',   // Yellow for medium
                    'rgba(220, 53, 69, 0.6)',   // Red for poor
                    'rgba(108, 117, 125, 0.6)'  // Gray for unknown
                ],
                borderColor: [
                    'rgba(40, 167, 69, 1)',
                    'rgba(255, 193, 7, 1)',
                    'rgba(220, 53, 69, 1)',
                    'rgba(108, 117, 125, 1)'
                ],
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: 'Network Quality Distribution'
                },
                legend: {
                    position: 'bottom'
                }
            }
        }
    });
}

function createTemporalChart(clusters) {
    const ctx = document.getElementById('temporalChart');
    if (!ctx) return;

    if (charts.temporal) {
        charts.temporal.destroy();
    }

    const hours = Array.from({length: 24}, (_, i) => i);
    const activityData = new Array(24).fill(0);

    // Simulate hourly activity based on peak hours
    clusters.forEach(cluster => {
        cluster.peak_hours.forEach(hour => {
            if (hour >= 0 && hour < 24) {
                activityData[hour] += cluster.activity_score;
            }
        });
    });

    charts.temporal = new Chart(ctx, {
        type: 'line',
        data: {
            labels: hours.map(h => h + ':00'),
            datasets: [{
                label: 'Activity Score',
                data: activityData,
                borderColor: 'rgba(102, 126, 234, 1)',
                backgroundColor: 'rgba(102, 126, 234, 0.1)',
                tension: 0.4,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: 'Daily Activity Pattern'
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Activity Score'
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: 'Hour of Day'
                    }
                }
            }
        }
    });
}

function showLoading() {
    document.getElementById('loading').style.display = 'block';
    document.getElementById('analysis-content').style.display = 'none';
}

function hideLoading() {
    document.getElementById('loading').style.display = 'none';
    document.getElementById('analysis-content').style.display = 'block';
}

function showError(message) {
    hideLoading();
    const container = document.querySelector('.container');
    const errorDiv = document.createElement('div');
    errorDiv.className = 'anomaly-alert';
    errorDiv.innerHTML = `<strong>Error:</strong> ${message}`;
    container.appendChild(errorDiv);

    setTimeout(() => {
        errorDiv.remove();
    }, 5000);
}

function updateLastUpdated() {
    const now = new Date();
    document.getElementById('last-updated').textContent = `Last updated: ${now.toLocaleTimeString()}`;
}
