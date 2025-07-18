use std::collections::{HashMap, HashSet};
use chrono::{DateTime, Utc, Duration};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use tracing::debug;
use crate::vector_db::PacketLike;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAnalyzer {
    crypto_analyzer: CryptoAnalyzer,
    traffic_analyzer: TrafficAnalyzer,
    device_profiler: DeviceProfiler,
    attack_detector: AttackDetector,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoAnalyzer {
    entropy_threshold: f64,
    known_weak_patterns: HashSet<String>,
    payload_history: HashMap<String, Vec<Vec<u8>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficAnalyzer {
    device_patterns: HashMap<String, TrafficPattern>,
    anomaly_threshold: f64,
    time_window: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficPattern {
    pub device_id: String,
    pub avg_interval: f64,
    pub packet_sizes: Vec<usize>,
    pub time_patterns: Vec<f64>,
    pub frequency_bands: HashMap<String, u32>,
    pub last_update: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceProfiler {
    device_profiles: HashMap<String, DeviceProfile>,
    fingerprints: HashMap<String, DeviceFingerprint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceProfile {
    pub device_id: String,
    pub manufacturer: Option<String>,
    pub device_type: Option<String>,
    pub behavior_baseline: BehaviorBaseline,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorBaseline {
    pub typical_intervals: Vec<f64>,
    pub typical_payload_sizes: Vec<usize>,
    pub typical_frequencies: Vec<String>,
    pub typical_spreading_factors: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceFingerprint {
    pub device_id: String,
    pub hardware_signature: String,
    pub timing_signature: Vec<f64>,
    pub payload_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackDetector {
    replay_detection: ReplayDetector,
    jamming_detection: JammingDetector,
    spoofing_detection: SpoofingDetector,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayDetector {
    message_hashes: HashMap<String, HashSet<String>>,
    time_window: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JammingDetector {
    signal_quality_history: HashMap<String, Vec<SignalQuality>>,
    threshold: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalQuality {
    pub timestamp: DateTime<Utc>,
    pub rssi: i32,
    pub snr: f64,
    pub packet_loss_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpoofingDetector {
    device_location_history: HashMap<String, Vec<LocationPoint>>,
    max_speed_threshold: f64, // km/h
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationPoint {
    pub timestamp: DateTime<Utc>,
    pub latitude: f64,
    pub longitude: f64,
    pub accuracy: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackFinding {
    pub attack_type: AttackType,
    pub severity: AttackSeverity,
    pub confidence: f64,
    pub description: String,
    pub indicators: Vec<String>,
    pub timestamp: DateTime<Utc>,
    pub affected_device: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttackType {
    Replay,
    Jamming,
    Spoofing,
    WeakCrypto,
    AnomalousTraffic,
    DeviceCloning,
    ManInTheMiddle,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttackSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFindings {
    pub findings: Vec<AttackFinding>,
    pub summary: SecuritySummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySummary {
    pub total_findings: usize,
    pub critical_findings: usize,
    pub high_findings: usize,
    pub affected_devices: usize,
    pub analysis_timestamp: DateTime<Utc>,
}

impl SecurityAnalyzer {
    pub fn new() -> Self {
        Self {
            crypto_analyzer: CryptoAnalyzer::new(),
            traffic_analyzer: TrafficAnalyzer::new(),
            device_profiler: DeviceProfiler::new(),
            attack_detector: AttackDetector::new(),
        }
    }

    pub fn analyze_message(&self, message: &crate::TtnMessage) -> Vec<crate::AuditFinding> {
        let mut findings = Vec::new();

        if let Some(device_ids) = &message.end_device_ids {
            let device_id = &device_ids.device_id;

            // Convert to simplified findings for now
            findings.push(crate::AuditFinding {
                check: "Security Analysis".to_string(),
                severity: crate::Severity::Info,
                details: format!("Security analysis completed for device {}", device_id),
                timestamp: Utc::now(),
                device_id: device_id.clone(),
                recommendation: None,
            });
        }

        findings
    }

    pub async fn analyze_packet<T>(&mut self, packet: &T) -> Vec<AttackFinding>
    where
        T: PacketLike + PacketLikeExt,
    {
        let mut findings = Vec::new();

        // Crypto analysis
        findings.extend(self.crypto_analyzer.analyze_payload(packet));

        // Traffic analysis
        findings.extend(self.traffic_analyzer.analyze_pattern(packet));

        // Device profiling
        findings.extend(self.device_profiler.analyze_device(packet));

        // Attack detection
        findings.extend(self.attack_detector.detect_attacks(packet).await);

        findings
    }
}

impl CryptoAnalyzer {
    pub fn new() -> Self {
        Self {
            entropy_threshold: 0.7,
            known_weak_patterns: HashSet::new(),
            payload_history: HashMap::new(),
        }
    }

    pub fn analyze_payload<T>(&mut self, packet: &T) -> Vec<AttackFinding>
    where
        T: PacketLike + PacketLikeExt,
    {
        let mut findings = Vec::new();

        if let Some(payload) = packet.get_payload() {
            let entropy = self.calculate_entropy(&payload);

            if entropy < self.entropy_threshold {
                findings.push(AttackFinding {
                    attack_type: AttackType::WeakCrypto,
                    severity: AttackSeverity::Medium,
                    confidence: 1.0 - entropy,
                    description: format!("Low entropy payload detected ({})", entropy),
                    indicators: vec!["Low entropy".to_string()],
                    timestamp: Utc::now(),
                    affected_device: packet.get_device_id(),
                });
            }
        }

        findings
    }

    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        let mut freq = [0u32; 256];
        for &byte in data {
            freq[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &freq {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy / 8.0 // Normalize to 0-1 range
    }
}

impl TrafficAnalyzer {
    pub fn new() -> Self {
        Self {
            device_patterns: HashMap::new(),
            anomaly_threshold: 0.8,
            time_window: Duration::hours(1),
        }
    }

    pub fn analyze_pattern<T>(&mut self, packet: &T) -> Vec<AttackFinding>
    where
        T: PacketLike + PacketLikeExt,
    {
        let mut findings = Vec::new();
        let device_id = packet.get_device_id();

        // Calculate anomaly score first
        let anomaly_score = 0.5; // Simple placeholder calculation

        // Update device pattern
        let _pattern = self.device_patterns.entry(device_id.clone())
            .or_insert_with(|| TrafficPattern {
                device_id: device_id.clone(),
                avg_interval: 0.0,
                packet_sizes: Vec::new(),
                time_patterns: Vec::new(),
                frequency_bands: HashMap::new(),
                last_update: Utc::now(),
            });

        if anomaly_score > self.anomaly_threshold {
            findings.push(AttackFinding {
                attack_type: AttackType::AnomalousTraffic,
                severity: AttackSeverity::Medium,
                confidence: anomaly_score,
                description: format!("Anomalous traffic pattern detected (score: {:.2})", anomaly_score),
                indicators: vec!["Unusual timing".to_string(), "Atypical packet size".to_string()],
                timestamp: Utc::now(),
                affected_device: device_id,
            });
        }

        findings
    }

    fn calculate_anomaly_score(&self, _pattern: &TrafficPattern) -> f64 {
        // Simple anomaly detection based on pattern deviation
        0.5 // Placeholder implementation
    }
}

impl DeviceProfiler {
    pub fn new() -> Self {
        Self {
            device_profiles: HashMap::new(),
            fingerprints: HashMap::new(),
        }
    }

    pub fn analyze_device<T>(&mut self, packet: &T) -> Vec<AttackFinding>
    where
        T: PacketLike + PacketLikeExt,
    {
        let mut findings = Vec::new();
        let device_id = packet.get_device_id();

        // Create or update device profile
        let profile = self.device_profiles.entry(device_id.clone())
            .or_insert_with(|| DeviceProfile {
                device_id: device_id.clone(),
                manufacturer: None,
                device_type: None,
                behavior_baseline: BehaviorBaseline {
                    typical_intervals: Vec::new(),
                    typical_payload_sizes: Vec::new(),
                    typical_frequencies: Vec::new(),
                    typical_spreading_factors: Vec::new(),
                },
                first_seen: Utc::now(),
                last_seen: Utc::now(),
            });

        profile.last_seen = Utc::now();

        findings
    }
}

impl AttackDetector {
    pub fn new() -> Self {
        Self {
            replay_detection: ReplayDetector {
                message_hashes: HashMap::new(),
                time_window: Duration::minutes(5),
            },
            jamming_detection: JammingDetector {
                signal_quality_history: HashMap::new(),
                threshold: 0.5,
            },
            spoofing_detection: SpoofingDetector {
                device_location_history: HashMap::new(),
                max_speed_threshold: 100.0, // 100 km/h
            },
        }
    }

    pub async fn detect_attacks<T>(&mut self, packet: &T) -> Vec<AttackFinding>
    where
        T: PacketLike + PacketLikeExt,
    {
        let mut findings = Vec::new();

        // Replay detection
        findings.extend(self.detect_replay_attack(packet).await);

        // Jamming detection
        findings.extend(self.detect_jamming_attack(packet).await);

        // Spoofing detection
        findings.extend(self.detect_spoofing_attack(packet).await);

        findings
    }

    pub async fn detect_replay_attack<T>(&mut self, packet: &T) -> Vec<AttackFinding>
    where
        T: PacketLike + PacketLikeExt,
    {
        let mut findings = Vec::new();

        if let Some(payload) = packet.get_payload() {
            let mut hasher = Sha256::new();
            hasher.update(payload);
            let hash = hex::encode(hasher.finalize());

            let device_id = packet.get_device_id();
            let device_hashes = self.replay_detection.message_hashes
                .entry(device_id.clone())
                .or_insert_with(HashSet::new);

            if device_hashes.contains(&hash) {
                findings.push(AttackFinding {
                    attack_type: AttackType::Replay,
                    severity: AttackSeverity::Critical,
                    confidence: 0.9,
                    description: "Potential replay attack detected - duplicate message hash".to_string(),
                    indicators: vec!["Duplicate payload hash".to_string()],
                    timestamp: Utc::now(),
                    affected_device: device_id,
                });
            } else {
                device_hashes.insert(hash);
            }
        }

        findings
    }

    pub async fn detect_jamming_attack<T>(&mut self, _packet: &T) -> Vec<AttackFinding>
    where
        T: PacketLike + PacketLikeExt,
    {
        // Placeholder for jamming detection
        Vec::new()
    }

    pub async fn detect_spoofing_attack<T>(&mut self, _packet: &T) -> Vec<AttackFinding>
    where
        T: PacketLike + PacketLikeExt,
    {
        // Placeholder for spoofing detection
        Vec::new()
    }

    pub async fn detect_timing_attack<T>(&mut self, _packet: &T) -> Vec<AttackFinding>
    where
        T: PacketLike + PacketLikeExt,
    {
        // Placeholder for timing attack detection
        Vec::new()
    }
}

// Extension trait for additional packet methods needed by security analyzer
pub trait PacketLikeExt: PacketLike {
    fn get_payload(&self) -> Option<&[u8]>;
    fn get_signal_quality(&self) -> Option<SignalQuality>;
    fn get_location(&self) -> Option<LocationPoint>;
}

// Implementation for the OfflinePacket type
impl PacketLikeExt for crate::dataset_processor::OfflinePacket {
    fn get_payload(&self) -> Option<&[u8]> {
        self.payload.as_ref().map(|p| p.as_bytes())
    }

    fn get_signal_quality(&self) -> Option<SignalQuality> {
        Some(SignalQuality {
            timestamp: self.timestamp,
            rssi: self.rssi.unwrap_or(-100),
            snr: self.snr.unwrap_or(0.0),
            packet_loss_rate: 0.0, // Calculate based on frame counter gaps
        })
    }

    fn get_location(&self) -> Option<LocationPoint> {
        None // No location data in OfflinePacket
    }
}
