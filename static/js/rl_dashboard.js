// RL Dashboard JavaScript

class RLDashboard {
    constructor() {
        this.metricsChart = null;
        this.statusUpdateInterval = null;
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.loadInitialData();
        this.startStatusUpdates();
        this.initializeMetricsChart();
    }

    setupEventListeners() {
        // Control buttons
        document.getElementById('init-btn').addEventListener('click', () => this.initializeRLPipeline());
        document.getElementById('train-btn').addEventListener('click', () => this.trainAgent());
        document.getElementById('validate-btn').addEventListener('click', () => this.validateAgent());
        document.getElementById('simulate-btn').addEventListener('click', () => this.simulateAction());
        document.getElementById('refresh-recommendations').addEventListener('click', () => this.loadRecommendations());
    }

    async loadInitialData() {
        await Promise.all([
            this.loadRLStatus(),
            this.loadRecommendations()
        ]);
    }

    startStatusUpdates() {
        // Update status every 10 seconds
        this.statusUpdateInterval = setInterval(() => {
            this.loadRLStatus();
        }, 10000);
    }

    async loadRLStatus() {
        try {
            const response = await fetch('/api/rl/status');
            const data = await response.json();

            // Update status cards
            document.getElementById('agent-status').textContent = data.status;
            document.getElementById('episodes-trained').textContent = data.agent_info.episodes_trained;
            document.getElementById('q-table-size').textContent = data.metrics.q_table_size;
            document.getElementById('avg-q-value').textContent = data.metrics.avg_q_value.toFixed(2);

            // Update metrics chart if we have data
            if (this.metricsChart && data.metrics) {
                this.updateMetricsChart(data.metrics);
            }

        } catch (error) {
            console.error('Failed to load RL status:', error);
            this.showToast('Failed to load RL status', 'error');
        }
    }

    async initializeRLPipeline() {
        const button = document.getElementById('init-btn');
        const originalText = button.innerHTML;

        try {
            button.disabled = true;
            button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Initializing...';

            this.showLoading('Initializing RL Pipeline...');

            const response = await fetch('/api/rl/initialize', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            const data = await response.json();

            if (response.ok) {
                this.showToast('RL Pipeline initialized successfully!', 'success');
                this.addLogEntry('RL Pipeline initialized with sample data', 'success');
                await this.loadRLStatus();
            } else {
                throw new Error(data.message || 'Initialization failed');
            }

        } catch (error) {
            console.error('Initialization failed:', error);
            this.showToast(`Initialization failed: ${error.message}`, 'error');
            this.addLogEntry(`Initialization failed: ${error.message}`, 'error');
        } finally {
            this.hideLoading();
            button.disabled = false;
            button.innerHTML = originalText;
        }
    }

    async trainAgent() {
        const button = document.getElementById('train-btn');
        const episodesInput = document.getElementById('episodes-input');
        const episodes = parseInt(episodesInput.value) || 100;
        const originalText = button.innerHTML;

        try {
            button.disabled = true;
            button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Training...';

            this.showLoading(`Training RL Agent for ${episodes} episodes...`);
            this.addLogEntry(`Starting training for ${episodes} episodes...`, 'info');

            // Start progress simulation
            this.simulateTrainingProgress(episodes);

            const response = await fetch('/api/rl/train', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ episodes })
            });

            const data = await response.json();

            if (response.ok) {
                this.showToast(`Training completed! ${data.episodes_trained} episodes trained.`, 'success');
                this.addLogEntry(`Training completed successfully: ${data.episodes_trained} episodes`, 'success');
                this.setProgress(100, 'Training completed');
                await this.loadRLStatus();
            } else {
                throw new Error(data.message || 'Training failed');
            }

        } catch (error) {
            console.error('Training failed:', error);
            this.showToast(`Training failed: ${error.message}`, 'error');
            this.addLogEntry(`Training failed: ${error.message}`, 'error');
            this.setProgress(0, 'Training failed');
        } finally {
            this.hideLoading();
            button.disabled = false;
            button.innerHTML = originalText;
        }
    }

    async validateAgent() {
        const button = document.getElementById('validate-btn');
        const originalText = button.innerHTML;

        try {
            button.disabled = true;
            button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Validating...';

            this.showLoading('Validating RL Agent...');
            this.addLogEntry('Starting agent validation...', 'info');

            const response = await fetch('/api/rl/validate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            const data = await response.json();

            if (response.ok) {
                this.showToast('Agent validation completed successfully!', 'success');
                this.addLogEntry('Validation completed successfully', 'success');

                // Display validation metrics if available
                if (data.metrics) {
                    this.addLogEntry(`Validation metrics: ${JSON.stringify(data.metrics)}`, 'info');
                }
            } else {
                throw new Error(data.message || 'Validation failed');
            }

        } catch (error) {
            console.error('Validation failed:', error);
            this.showToast(`Validation failed: ${error.message}`, 'error');
            this.addLogEntry(`Validation failed: ${error.message}`, 'error');
        } finally {
            this.hideLoading();
            button.disabled = false;
            button.innerHTML = originalText;
        }
    }

    async loadRecommendations() {
        try {
            this.showLoading('Loading AI recommendations...');

            const response = await fetch('/api/rl/recommendations');
            const recommendations = await response.json();

            const container = document.getElementById('recommendations-container');

            if (recommendations.length === 0) {
                container.innerHTML = `
                    <div class="no-recommendations">
                        <p>No recommendations available. Initialize and train the RL agent first.</p>
                    </div>
                `;
                return;
            }

            container.innerHTML = recommendations.map(rec => this.createRecommendationCard(rec)).join('');

        } catch (error) {
            console.error('Failed to load recommendations:', error);
            this.showToast('Failed to load recommendations', 'error');
        } finally {
            this.hideLoading();
        }
    }

    createRecommendationCard(recommendation) {
        const confidenceColor = recommendation.confidence > 0.7 ? '#10b981' :
                               recommendation.confidence > 0.4 ? '#f59e0b' : '#ef4444';

        return `
            <div class="recommendation-card">
                <div class="device-header">
                    <span class="device-id">${recommendation.device_id}</span>
                    <span class="confidence-badge" style="background: ${confidenceColor}">
                        ${(recommendation.confidence * 100).toFixed(0)}% Confidence
                    </span>
                </div>

                <div class="recommendation-details">
                    <div class="current-state">
                        <h4>Current Network State</h4>
                        <div class="state-grid">
                            <span>SF: ${recommendation.current_state.spreading_factor}</span>
                            <span>Power: ${recommendation.current_state.transmit_power} dBm</span>
                            <span>RSSI: ${recommendation.current_state.rssi} dBm</span>
                            <span>Loss Rate: ${(recommendation.current_state.packet_loss_rate * 100).toFixed(1)}%</span>
                        </div>
                    </div>

                    <div class="recommended-action">
                        <h4>Recommended Action</h4>
                        <span class="action-tag">${this.formatActionName(recommendation.recommended_action)}</span>
                    </div>
                </div>

                <div class="expected-reward">
                    <strong>Expected Reward: ${recommendation.expected_reward.toFixed(2)}</strong>
                </div>
            </div>
        `;
    }

    formatActionName(action) {
        const actionMap = {
            'IncreaseSF': 'Increase Spreading Factor',
            'DecreaseSF': 'Decrease Spreading Factor',
            'IncreasePower': 'Increase Transmit Power',
            'DecreasePower': 'Decrease Transmit Power',
            'ChangeChannel': 'Change Channel',
            'NoAction': 'No Action Required'
        };
        return actionMap[action] || action;
    }

    async simulateAction() {
        const button = document.getElementById('simulate-btn');
        const originalText = button.innerHTML;

        try {
            button.disabled = true;
            button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Simulating...';

            // Gather simulation parameters
            const networkState = {
                spreading_factor: parseInt(document.getElementById('sim-sf').value),
                transmit_power: parseFloat(document.getElementById('sim-power').value),
                data_rate: parseFloat(document.getElementById('sim-datarate').value),
                channel_utilization: parseFloat(document.getElementById('sim-channel-util').value),
                packet_loss_rate: parseFloat(document.getElementById('sim-packet-loss').value),
                energy_consumption: 20.0, // Default
                network_congestion: 0.2, // Default
                rssi: parseFloat(document.getElementById('sim-rssi').value),
                snr: 5.0, // Default
                device_battery_level: 0.8 // Default
            };

            const action = document.getElementById('sim-action').value;

            const response = await fetch('/api/rl/simulate-action', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    network_state: networkState,
                    action: action
                })
            });

            const data = await response.json();

            if (response.ok) {
                this.displaySimulationResults(data);
                this.showToast('Action simulation completed!', 'success');
            } else {
                throw new Error(data.message || 'Simulation failed');
            }

        } catch (error) {
            console.error('Simulation failed:', error);
            this.showToast(`Simulation failed: ${error.message}`, 'error');
        } finally {
            button.disabled = false;
            button.innerHTML = originalText;
        }
    }

    displaySimulationResults(data) {
        const output = document.getElementById('simulation-output');

        output.innerHTML = `
            <div class="simulation-result">
                <h4>✅ Simulation Completed Successfully</h4>

                <div class="result-section">
                    <h5>Action Taken:</h5>
                    <p><strong>${this.formatActionName(data.action)}</strong></p>
                </div>

                <div class="result-section">
                    <h5>Initial State:</h5>
                    <ul>
                        <li>Spreading Factor: ${data.initial_state.spreading_factor}</li>
                        <li>Transmit Power: ${data.initial_state.transmit_power} dBm</li>
                        <li>RSSI: ${data.initial_state.rssi} dBm</li>
                        <li>Packet Loss Rate: ${(data.initial_state.packet_loss_rate * 100).toFixed(1)}%</li>
                    </ul>
                </div>

                <div class="result-section">
                    <h5>Predicted Next State:</h5>
                    <ul>
                        <li>Spreading Factor: ${data.next_state.spreading_factor}</li>
                        <li>Transmit Power: ${data.next_state.transmit_power} dBm</li>
                        <li>RSSI: ${data.next_state.rssi} dBm</li>
                        <li>Packet Loss Rate: ${(data.next_state.packet_loss_rate * 100).toFixed(1)}%</li>
                    </ul>
                </div>

                <div class="result-section reward-section">
                    <h5>Reward Score:</h5>
                    <p class="reward-value ${data.reward > 0 ? 'positive' : 'negative'}">
                        ${data.reward.toFixed(2)}
                    </p>
                    <p class="reward-explanation">
                        ${data.reward > 0 ? 'Positive reward indicates beneficial action' : 'Negative reward suggests suboptimal action'}
                    </p>
                </div>
            </div>
        `;

        // Add some CSS for the simulation results
        if (!document.getElementById('simulation-results-style')) {
            const style = document.createElement('style');
            style.id = 'simulation-results-style';
            style.textContent = `
                .simulation-result h4 { color: #10b981; margin-bottom: 1rem; }
                .result-section { margin-bottom: 1rem; padding: 0.5rem 0; border-bottom: 1px solid #e5e7eb; }
                .result-section:last-child { border-bottom: none; }
                .result-section h5 { color: #4f46e5; margin-bottom: 0.5rem; }
                .result-section ul { list-style: none; padding-left: 1rem; }
                .result-section li { margin-bottom: 0.25rem; color: #6b7280; }
                .reward-value { font-size: 1.5rem; font-weight: bold; }
                .reward-value.positive { color: #10b981; }
                .reward-value.negative { color: #ef4444; }
                .reward-explanation { font-size: 0.9rem; color: #6b7280; margin-top: 0.5rem; }
            `;
            document.head.appendChild(style);
        }
    }

    simulateTrainingProgress(episodes) {
        let currentEpisode = 0;
        const progressInterval = setInterval(() => {
            currentEpisode += Math.floor(Math.random() * 5) + 1;
            const progress = Math.min((currentEpisode / episodes) * 100, 100);

            this.setProgress(progress, `Training... Episode ${Math.min(currentEpisode, episodes)}/${episodes}`);

            if (currentEpisode >= episodes) {
                clearInterval(progressInterval);
            }
        }, 100);
    }

    setProgress(percentage, text) {
        document.getElementById('progress-fill').style.width = `${percentage}%`;
        document.getElementById('progress-text').textContent = text;
        document.getElementById('progress-percentage').textContent = `${Math.round(percentage)}%`;
    }

    addLogEntry(message, type = 'info') {
        const logContainer = document.getElementById('training-log');
        const timestamp = new Date().toLocaleTimeString();
        const entry = document.createElement('p');
        entry.className = `log-entry ${type}`;
        entry.textContent = `[${timestamp}] ${message}`;

        logContainer.appendChild(entry);
        logContainer.scrollTop = logContainer.scrollHeight;

        // Keep only last 50 entries
        while (logContainer.children.length > 50) {
            logContainer.removeChild(logContainer.firstChild);
        }
    }

    initializeMetricsChart() {
        const ctx = document.getElementById('metricsChart').getContext('2d');

        this.metricsChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Episodes Trained',
                    data: [],
                    borderColor: '#4f46e5',
                    backgroundColor: 'rgba(79, 70, 229, 0.1)',
                    tension: 0.4
                }, {
                    label: 'Q-Table Size',
                    data: [],
                    borderColor: '#10b981',
                    backgroundColor: 'rgba(16, 185, 129, 0.1)',
                    tension: 0.4,
                    yAxisID: 'y1'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: {
                        display: true,
                        text: 'RL Agent Training Progress'
                    }
                },
                scales: {
                    y: {
                        type: 'linear',
                        display: true,
                        position: 'left',
                        title: {
                            display: true,
                            text: 'Episodes'
                        }
                    },
                    y1: {
                        type: 'linear',
                        display: true,
                        position: 'right',
                        title: {
                            display: true,
                            text: 'Q-Table Size'
                        },
                        grid: {
                            drawOnChartArea: false,
                        },
                    }
                }
            }
        });
    }

    updateMetricsChart(metrics) {
        if (!this.metricsChart) return;

        const now = new Date().toLocaleTimeString();
        const chart = this.metricsChart;

        // Add new data point
        chart.data.labels.push(now);
        chart.data.datasets[0].data.push(metrics.episodes_trained || 0);
        chart.data.datasets[1].data.push(metrics.q_table_size || 0);

        // Keep only last 20 data points
        if (chart.data.labels.length > 20) {
            chart.data.labels.shift();
            chart.data.datasets.forEach(dataset => dataset.data.shift());
        }

        chart.update('none');
    }

    showLoading(text = 'Loading...') {
        const overlay = document.getElementById('loading-overlay');
        const loadingText = document.getElementById('loading-text');
        loadingText.textContent = text;
        overlay.style.display = 'flex';
    }

    hideLoading() {
        document.getElementById('loading-overlay').style.display = 'none';
    }

    showToast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.innerHTML = `
            <div style="display: flex; align-items: center; gap: 10px;">
                <i class="fas fa-${this.getToastIcon(type)}"></i>
                <span>${message}</span>
            </div>
        `;

        container.appendChild(toast);

        // Auto remove after 5 seconds
        setTimeout(() => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, 5000);
    }

    getToastIcon(type) {
        const icons = {
            success: 'check-circle',
            error: 'exclamation-circle',
            warning: 'exclamation-triangle',
            info: 'info-circle'
        };
        return icons[type] || 'info-circle';
    }

    destroy() {
        if (this.statusUpdateInterval) {
            clearInterval(this.statusUpdateInterval);
        }
        if (this.metricsChart) {
            this.metricsChart.destroy();
        }
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.rlDashboard = new RLDashboard();
});

// Cleanup when page unloads
window.addEventListener('beforeunload', () => {
    if (window.rlDashboard) {
        window.rlDashboard.destroy();
    }
});
