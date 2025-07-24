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

        // File upload event listeners
        this.setupFileUploadListeners();
    }

    setupFileUploadListeners() {
        // Training data upload
        const trainingDataUpload = document.getElementById('training-data-upload');
        const uploadTrainingBtn = document.getElementById('upload-training-btn');

        trainingDataUpload.addEventListener('change', (e) => this.handleFileSelection(e, 'training'));
        uploadTrainingBtn.addEventListener('click', () => this.uploadFiles('training'));

        // Model upload
        const modelUpload = document.getElementById('model-upload');
        const uploadModelBtn = document.getElementById('upload-model-btn');

        modelUpload.addEventListener('change', (e) => this.handleFileSelection(e, 'model'));
        uploadModelBtn.addEventListener('click', () => this.uploadFiles('model'));

        // Config upload
        const configUpload = document.getElementById('config-upload');
        const uploadConfigBtn = document.getElementById('upload-config-btn');

        configUpload.addEventListener('change', (e) => this.handleFileSelection(e, 'config'));
        uploadConfigBtn.addEventListener('click', () => this.uploadFiles('config'));

        // Export buttons
        document.getElementById('export-model-btn').addEventListener('click', () => this.exportData('model'));
        document.getElementById('export-qtable-btn').addEventListener('click', () => this.exportData('qtable'));
        document.getElementById('export-logs-btn').addEventListener('click', () => this.exportData('logs'));
        document.getElementById('export-metrics-btn').addEventListener('click', () => this.exportData('metrics'));

        // Drag and drop functionality
        this.setupDragAndDrop();
    }

    setupDragAndDrop() {
        const fileInputs = [
            { element: document.getElementById('training-data-upload'), type: 'training' },
            { element: document.getElementById('model-upload'), type: 'model' },
            { element: document.getElementById('config-upload'), type: 'config' }
        ];

        fileInputs.forEach(({ element, type }) => {
            const container = element.closest('.file-input-container');

            ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
                container.addEventListener(eventName, this.preventDefaults, false);
            });

            ['dragenter', 'dragover'].forEach(eventName => {
                container.addEventListener(eventName, () => container.classList.add('drag-over'), false);
            });

            ['dragleave', 'drop'].forEach(eventName => {
                container.addEventListener(eventName, () => container.classList.remove('drag-over'), false);
            });

            container.addEventListener('drop', (e) => this.handleDrop(e, type), false);
        });
    }

    preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    handleDrop(e, type) {
        const files = e.dataTransfer.files;
        this.processSelectedFiles(files, type);
    }

    handleFileSelection(e, type) {
        const files = e.target.files;
        this.processSelectedFiles(files, type);
    }

    processSelectedFiles(files, type) {
        const fileArray = Array.from(files);

        if (fileArray.length === 0) return;

        // Store files for later upload
        this[`${type}Files`] = fileArray;

        // Update UI
        this.updateFileList(fileArray, type);
        this.enableUploadButton(type);
    }

    updateFileList(files, type) {
        const listContainer = document.getElementById(`${type === 'training' ? 'training-files-list' : type + '-file-info'}`);

        if (type === 'training') {
            // Multiple files for training data
            listContainer.innerHTML = files.map(file => `
                <div class="file-item">
                    <span class="file-name">${file.name}</span>
                    <span class="file-size">${this.formatFileSize(file.size)}</span>
                    <button class="file-remove" onclick="rlDashboard.removeFile('${type}', '${file.name}')">×</button>
                </div>
            `).join('');
        } else {
            // Single file for model/config
            const file = files[0];
            listContainer.innerHTML = `
                <div class="file-info-content">
                    <strong>${file.name}</strong><br>
                    <span class="file-meta">Size: ${this.formatFileSize(file.size)} | Type: ${file.type || 'Unknown'}</span>
                </div>
            `;
        }
    }

    enableUploadButton(type) {
        const button = document.getElementById(`upload-${type === 'training' ? 'training' : type}-btn`);
        button.disabled = false;
    }

    removeFile(type, fileName) {
        if (this[`${type}Files`]) {
            this[`${type}Files`] = this[`${type}Files`].filter(file => file.name !== fileName);
            this.updateFileList(this[`${type}Files`], type);

            if (this[`${type}Files`].length === 0) {
                document.getElementById(`upload-${type === 'training' ? 'training' : type}-btn`).disabled = true;
            }
        }
    }

    async uploadFiles(type) {
        const files = this[`${type}Files`];
        if (!files || files.length === 0) {
            this.showToast('No files selected for upload', 'warning');
            return;
        }

        const button = document.getElementById(`upload-${type === 'training' ? 'training' : type}-btn`);
        const originalText = button.innerHTML;

        try {
            button.disabled = true;
            button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Uploading...';

            this.showUploadProgress();

            const formData = new FormData();
            files.forEach(file => {
                formData.append('files', file);
            });
            formData.append('type', type);

            const response = await fetch('/api/rl/upload', {
                method: 'POST',
                body: formData,
                onUploadProgress: (progressEvent) => {
                    const progress = (progressEvent.loaded / progressEvent.total) * 100;
                    this.updateUploadProgress(progress);
                }
            });

            const data = await response.json();

            if (response.ok) {
                this.showToast(`${type === 'training' ? 'Training data' : type + ' file'} uploaded successfully!`, 'success');
                this.addLogEntry(`Uploaded ${files.length} ${type} file(s)`, 'success');
                this.updateUploadedFilesList(data.uploaded_files, type);
                this.clearFileSelection(type);

                // Refresh status if training data was uploaded
                if (type === 'training') {
                    await this.loadRLStatus();
                }
            } else {
                throw new Error(data.message || 'Upload failed');
            }

        } catch (error) {
            console.error('Upload failed:', error);
            this.showToast(`Upload failed: ${error.message}`, 'error');
            this.addLogEntry(`Upload failed: ${error.message}`, 'error');
        } finally {
            this.hideUploadProgress();
            button.disabled = true;
            button.innerHTML = originalText;
        }
    }

    showUploadProgress() {
        document.getElementById('upload-progress').style.display = 'block';
        this.updateUploadProgress(0);
    }

    updateUploadProgress(percentage) {
        document.getElementById('upload-progress-fill').style.width = `${percentage}%`;
        document.getElementById('upload-percentage').textContent = `${Math.round(percentage)}%`;
        document.getElementById('upload-status-text').textContent =
            percentage < 100 ? 'Uploading...' : 'Upload complete';
    }

    hideUploadProgress() {
        setTimeout(() => {
            document.getElementById('upload-progress').style.display = 'none';
        }, 1000);
    }

    clearFileSelection(type) {
        // Clear the file input
        const input = document.getElementById(`${type === 'training' ? 'training-data' : type}-upload`);
        input.value = '';

        // Clear stored files
        this[`${type}Files`] = [];

        // Clear file list/info display
        const listContainer = document.getElementById(`${type === 'training' ? 'training-files-list' : type + '-file-info'}`);
        listContainer.innerHTML = '';

        // Disable upload button
        document.getElementById(`upload-${type === 'training' ? 'training' : type}-btn`).disabled = true;
    }

    updateUploadedFilesList(uploadedFiles, type) {
        const container = document.getElementById(`uploaded-${type === 'training' ? 'training' : type}-files`);

        // Remove "no files" message if present
        const noFilesMsg = container.querySelector('.no-files');
        if (noFilesMsg) {
            noFilesMsg.remove();
        }

        uploadedFiles.forEach(file => {
            const fileElement = document.createElement('div');
            fileElement.className = 'uploaded-file-item';
            fileElement.innerHTML = `
                <div class="uploaded-file-info">
                    <div class="uploaded-file-name">${file.name}</div>
                    <div class="uploaded-file-meta">${this.formatFileSize(file.size)} • Uploaded ${new Date(file.upload_time).toLocaleString()}</div>
                </div>
                <div class="uploaded-file-actions">
                    <button class="file-action-btn download" onclick="rlDashboard.downloadFile('${file.id}', '${file.name}')">⬇</button>
                    <button class="file-action-btn use" onclick="rlDashboard.useFile('${file.id}', '${type}')">Use</button>
                    <button class="file-action-btn delete" onclick="rlDashboard.deleteUploadedFile('${file.id}', '${type}')">×</button>
                </div>
            `;
            container.appendChild(fileElement);
        });
    }

    async downloadFile(fileId, fileName) {
        try {
            const response = await fetch(`/api/rl/download/${fileId}`);

            if (response.ok) {
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = fileName;
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                document.body.removeChild(a);

                this.showToast('File downloaded successfully', 'success');
            } else {
                throw new Error('Download failed');
            }
        } catch (error) {
            console.error('Download failed:', error);
            this.showToast('Download failed', 'error');
        }
    }

    async useFile(fileId, type) {
        try {
            this.showLoading(`Loading ${type} file...`);

            const response = await fetch(`/api/rl/use-file/${fileId}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ type })
            });

            const data = await response.json();

            if (response.ok) {
                this.showToast(`${type} file loaded successfully!`, 'success');
                this.addLogEntry(`Loaded ${type} file: ${data.file_name}`, 'success');

                // Refresh status after loading
                await this.loadRLStatus();
            } else {
                throw new Error(data.message || 'Failed to load file');
            }
        } catch (error) {
            console.error('Failed to use file:', error);
            this.showToast(`Failed to load file: ${error.message}`, 'error');
        } finally {
            this.hideLoading();
        }
    }

    async deleteUploadedFile(fileId, type) {
        if (!confirm('Are you sure you want to delete this file?')) {
            return;
        }

        try {
            const response = await fetch(`/api/rl/delete-file/${fileId}`, {
                method: 'DELETE'
            });

            if (response.ok) {
                // Remove file element from UI
                const fileElement = document.querySelector(`[onclick*="${fileId}"]`).closest('.uploaded-file-item');
                fileElement.remove();

                // Check if container is empty and add "no files" message
                const container = document.getElementById(`uploaded-${type === 'training' ? 'training' : type}-files`);
                if (container.children.length === 0) {
                    container.innerHTML = '<p class="no-files">No files uploaded</p>';
                }

                this.showToast('File deleted successfully', 'success');
            } else {
                throw new Error('Delete failed');
            }
        } catch (error) {
            console.error('Delete failed:', error);
            this.showToast('Failed to delete file', 'error');
        }
    }

    async exportData(type) {
        try {
            this.showLoading(`Exporting ${type}...`);

            const response = await fetch(`/api/rl/export/${type}`, {
                method: 'POST'
            });

            if (response.ok) {
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `rl_${type}_${new Date().toISOString().split('T')[0]}.json`;
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                document.body.removeChild(a);

                this.showToast(`${type} exported successfully!`, 'success');
                this.addLogEntry(`Exported ${type} data`, 'success');
            } else {
                const data = await response.json();
                throw new Error(data.message || 'Export failed');
            }
        } catch (error) {
            console.error('Export failed:', error);
            this.showToast(`Export failed: ${error.message}`, 'error');
        } finally {
            this.hideLoading();
        }
    }

    formatFileSize(bytes) {
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        if (bytes === 0) return '0 Bytes';
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
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

            // Update status cards with null checks
            document.getElementById('agent-status').textContent = data.status || 'Unknown';
            document.getElementById('episodes-trained').textContent = data.agent_info?.episodes_trained || 0;
            document.getElementById('q-table-size').textContent = data.metrics?.q_table_size || 0;

            // Safely handle avg_q_value with null check and NaN check
            const avgQValue = data.metrics?.avg_q_value;
            const avgQDisplay = (avgQValue !== null && avgQValue !== undefined && !isNaN(avgQValue))
                ? avgQValue.toFixed(2)
                : '0.00';
            document.getElementById('avg-q-value').textContent = avgQDisplay;

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
