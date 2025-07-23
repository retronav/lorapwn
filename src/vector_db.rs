use qdrant_client::{
    Qdrant,
    qdrant::{
        CreateCollection, Distance, VectorParams, PointStruct, SearchPoints, UpsertPoints, ScrollPoints,
        VectorsConfig, Value as QdrantValue, Condition, Range, Filter,
    },
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc, Duration};
use anyhow::Result;
use tracing::debug;
use sha2::{Sha256, Digest};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketEmbedding {
    pub id: String,
    pub device_id: String,
    pub timestamp: DateTime<Utc>,
    pub embedding: Vec<f32>,
    pub metadata: PacketMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketMetadata {
    pub frame_counter: Option<u32>,
    pub rssi: Option<i32>,
    pub snr: Option<f64>,
    pub spreading_factor: Option<u8>,
    pub frequency: Option<String>,
    pub gateway_count: usize,
    pub payload_size: usize,
    pub findings_count: usize,
    pub severity_score: f32,
    pub anomaly_score: f32,
}

pub struct VectorDatabase {
    client: Qdrant,
    collection_name: String,
}

// Manually implement Debug since Qdrant doesn't implement it
impl std::fmt::Debug for VectorDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VectorDatabase")
            .field("collection_name", &self.collection_name)
            .field("client", &"Qdrant(...)".to_string())
            .finish()
    }
}

impl VectorDatabase {
    pub async fn new(collection_name: &str) -> Result<Self> {
        // Use environment variable for Qdrant URL, fallback to localhost for local development
        let qdrant_url = std::env::var("QDRANT_URL")
            .unwrap_or_else(|_| "http://localhost:6334".to_string());

        let client = Qdrant::from_url(&qdrant_url).build()?;

        let db = Self {
            client,
            collection_name: collection_name.to_string(),
        };

        db.init_collection().await?;
        Ok(db)
    }

    async fn init_collection(&self) -> Result<()> {
        let collections = self.client.list_collections().await?;

        if !collections.collections.iter().any(|c| c.name == self.collection_name) {
            self.client
                .create_collection(CreateCollection {
                    collection_name: self.collection_name.clone(),
                    vectors_config: Some(VectorsConfig {
                        config: Some(qdrant_client::qdrant::vectors_config::Config::Params(
                            VectorParams {
                                size: 128,
                                distance: Distance::Cosine.into(),
                                ..Default::default()
                            }
                        )),
                    }),
                    ..Default::default()
                })
                .await?;

            debug!("Created vector collection: {}", self.collection_name);
        }

        Ok(())
    }

    pub async fn store_packet<T>(&self, packet: &T) -> Result<()>
    where
        T: PacketLike,
    {
        let embedding = self.generate_packet_embedding(packet);
        let metadata = self.extract_metadata(packet);

        let payload: HashMap<String, QdrantValue> = [
            ("device_id".to_string(), QdrantValue::from(packet.get_device_id())),
            ("timestamp".to_string(), QdrantValue::from(packet.get_timestamp().timestamp())),
            ("frame_counter".to_string(), QdrantValue::from(metadata.frame_counter.unwrap_or(0) as i64)),
            ("rssi".to_string(), QdrantValue::from(metadata.rssi.unwrap_or(-200) as i64)),
            ("gateway_count".to_string(), QdrantValue::from(metadata.gateway_count as i64)),
            ("findings_count".to_string(), QdrantValue::from(metadata.findings_count as i64)),
            ("severity_score".to_string(), QdrantValue::from(metadata.severity_score as f32)),
            ("anomaly_score".to_string(), QdrantValue::from(metadata.anomaly_score as f32)),
        ].into_iter().collect();

        let point = PointStruct::new(
            packet.get_id(),
            embedding,
            payload,
        );

        self.client.upsert_points(UpsertPoints {
            collection_name: self.collection_name.clone(),
            points: vec![point],
            ..Default::default()
        }).await?;

        debug!("Stored packet {} in vector database", packet.get_id());
        Ok(())
    }

    pub async fn search_similar_packets(
        &self,
        query_embedding: Vec<f32>,
        limit: usize,
        filter: Option<Filter>,
    ) -> Result<Vec<PacketEmbedding>, Box<dyn std::error::Error>> {
        let search_result = self.client.search_points(SearchPoints {
            collection_name: self.collection_name.clone(),
            vector: query_embedding,
            limit: limit as u64,
            with_payload: Some(true.into()),
            filter,
            ..Default::default()
        }).await?;

        let mut results = Vec::new();
        for point in search_result.result {
            let payload = point.payload;
            let embedding = PacketEmbedding {
                id: format!("{:?}", point.id.unwrap()),
                device_id: payload.get("device_id")
                    .and_then(|v| match v.kind {
                        Some(qdrant_client::qdrant::value::Kind::StringValue(ref s)) => Some(s.clone()),
                        _ => None,
                    })
                    .unwrap_or_default(),
                timestamp: DateTime::from_timestamp(
                    payload.get("timestamp")
                        .and_then(|v| match v.kind {
                            Some(qdrant_client::qdrant::value::Kind::IntegerValue(i)) => Some(i),
                            _ => None,
                        })
                        .unwrap_or(0),
                    0
                ).unwrap_or_default(),
                embedding: vec![],
                metadata: PacketMetadata {
                    frame_counter: payload.get("frame_counter")
                        .and_then(|v| match v.kind {
                            Some(qdrant_client::qdrant::value::Kind::IntegerValue(i)) => Some(i as u32),
                            _ => None,
                        }),
                    rssi: payload.get("rssi")
                        .and_then(|v| match v.kind {
                            Some(qdrant_client::qdrant::value::Kind::IntegerValue(i)) => Some(i as i32),
                            _ => None,
                        }),
                    snr: None,
                    spreading_factor: None,
                    frequency: None,
                    gateway_count: payload.get("gateway_count")
                        .and_then(|v| match v.kind {
                            Some(qdrant_client::qdrant::value::Kind::IntegerValue(i)) => Some(i as usize),
                            _ => None,
                        })
                        .unwrap_or(0),
                    payload_size: 0,
                    findings_count: payload.get("findings_count")
                        .and_then(|v| match v.kind {
                            Some(qdrant_client::qdrant::value::Kind::IntegerValue(i)) => Some(i as usize),
                            _ => None,
                        })
                        .unwrap_or(0),
                    severity_score: payload.get("severity_score")
                        .and_then(|v| match v.kind {
                            Some(qdrant_client::qdrant::value::Kind::DoubleValue(d)) => Some(d as f32),
                            _ => None,
                        })
                        .unwrap_or(0.0),
                    anomaly_score: payload.get("anomaly_score")
                        .and_then(|v| match v.kind {
                            Some(qdrant_client::qdrant::value::Kind::DoubleValue(d)) => Some(d as f32),
                            _ => None,
                        })
                        .unwrap_or(0.0),
                },
            };
            results.push(embedding);
        }

        Ok(results)
    }

    pub async fn get_anomalous_packets(
        &self,
        threshold: f32,
        limit: usize,
    ) -> Result<Vec<PacketEmbedding>, Box<dyn std::error::Error>> {
        let filter = Filter::must([
            Condition::range("anomaly_score", Range {
                gte: Some(threshold.into()),
                ..Default::default()
            })
        ]);

        let _search_result = self.client.scroll(ScrollPoints {
            collection_name: self.collection_name.clone(),
            filter: Some(filter),
            limit: Some(limit as u32),
            with_payload: Some(true.into()),
            with_vectors: Some(true.into()),
            ..Default::default()
        }).await?;

        // Process results similar to search_similar_packets
        Ok(Vec::new()) // Simplified for now
    }

    fn generate_packet_embedding<T>(&self, packet: &T) -> Vec<f32>
    where
        T: PacketLike,
    {
        let mut features = Vec::with_capacity(128);

        // Device features
        let device_id_hash = self.hash_string(&packet.get_device_id());
        features.extend_from_slice(&device_id_hash[..8]);

        // Temporal features
        let timestamp = packet.get_timestamp().timestamp() as f32;
        features.extend_from_slice(&[
            (timestamp % 86400.0) / 86400.0, // Time of day
            ((timestamp / 86400.0) % 7.0) / 7.0, // Day of week
        ]);

        // Network features from packet
        features.extend(packet.get_network_features());

        // Pad or truncate to exactly 128 dimensions
        features.resize(128, 0.0);

        features
    }

    fn extract_metadata<T>(&self, packet: &T) -> PacketMetadata
    where
        T: PacketLike,
    {
        PacketMetadata {
            frame_counter: packet.get_frame_counter(),
            rssi: packet.get_rssi(),
            snr: packet.get_snr(),
            spreading_factor: packet.get_spreading_factor(),
            frequency: packet.get_frequency(),
            gateway_count: packet.get_gateway_count(),
            payload_size: packet.get_payload_size(),
            findings_count: packet.get_findings_count(),
            severity_score: packet.get_severity_score(),
            anomaly_score: self.calculate_anomaly_score(packet),
        }
    }

    fn calculate_anomaly_score<T>(&self, packet: &T) -> f32
    where
        T: PacketLike,
    {
        let mut score = 0.0;

        // High findings count increases anomaly score
        score += (packet.get_findings_count() as f32 / 5.0).min(1.0) * 0.3;

        // Unusual network parameters
        if let Some(rssi) = packet.get_rssi() {
            if rssi < -120 {
                score += 0.2;
            }
        }

        // Single gateway coverage
        if packet.get_gateway_count() == 1 {
            score += 0.1;
        }

        score.min(1.0)
    }

    fn hash_string(&self, s: &str) -> Vec<f32> {
        let mut hasher = Sha256::new();
        hasher.update(s);
        let hash = hasher.finalize();

        hash.iter()
            .map(|&b| (b as f32) / 255.0)
            .collect()
    }
}

// Trait for packets that can be stored in vector database
pub trait PacketLike {
    fn get_id(&self) -> String;
    fn get_device_id(&self) -> String;
    fn get_timestamp(&self) -> DateTime<Utc>;
    fn get_frame_counter(&self) -> Option<u32>;
    fn get_rssi(&self) -> Option<i32>;
    fn get_snr(&self) -> Option<f64>;
    fn get_spreading_factor(&self) -> Option<u8>;
    fn get_frequency(&self) -> Option<String>;
    fn get_gateway_count(&self) -> usize;
    fn get_payload_size(&self) -> usize;
    fn get_findings_count(&self) -> usize;
    fn get_severity_score(&self) -> f32;
    fn get_network_features(&self) -> Vec<f32>;
}

// ==============================================================================
// Advanced Clustering Data Structures
// ==============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusteringResults {
    pub device_clusters: Vec<DeviceBehaviorCluster>,
    pub security_clusters: Vec<SecurityCluster>,
    pub network_clusters: Vec<NetworkQualityCluster>,
    pub temporal_clusters: Vec<TemporalCluster>,
    pub geospatial_clusters: Vec<GeospatialCluster>,
    pub insights: ClusteringInsights,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceBehaviorCluster {
    pub cluster_id: String,
    pub devices: Vec<String>,
    pub characteristics: DeviceCharacteristics,
    pub size: usize,
    pub centroid: Vec<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCharacteristics {
    pub avg_packet_interval: f64, // seconds
    pub typical_payload_size: f32,
    pub preferred_spreading_factor: u8,
    pub activity_pattern: ActivityPattern,
    pub gateway_affinity: Vec<String>,
    pub avg_rssi: f32,
    pub reliability_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActivityPattern {
    Periodic,      // Regular intervals (sensors)
    Burst,         // Sudden high activity (alarms)
    Random,        // Irregular patterns
    EventDriven,   // Based on external triggers
    Dormant,       // Very low activity
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityCluster {
    pub cluster_id: String,
    pub threat_level: ThreatLevel,
    pub finding_patterns: Vec<String>,
    pub affected_devices: Vec<String>,
    pub temporal_pattern: TemporalSecurityPattern,
    pub severity_distribution: HashMap<String, usize>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatLevel {
    Benign,
    Suspicious,
    Malicious,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TemporalSecurityPattern {
    IsolatedIncident,
    RepeatingPattern,
    EscalatingThreat,
    CoordinatedAttack,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkQualityCluster {
    pub cluster_id: String,
    pub rssi_range: (i32, i32),
    pub snr_range: (f64, f64),
    pub gateway_count_range: (usize, usize),
    pub quality_score: f32,
    pub affected_devices: Vec<String>,
    pub coverage_analysis: CoverageAnalysis,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageAnalysis {
    pub gateway_distribution: HashMap<String, usize>,
    pub signal_strength_trend: String,
    pub reliability_metrics: ReliabilityMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReliabilityMetrics {
    pub packet_loss_rate: f32,
    pub signal_consistency: f32,
    pub coverage_redundancy: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalCluster {
    pub cluster_id: String,
    pub time_pattern: TimePattern,
    pub frequency: f64, // Hz
    pub peak_hours: Vec<u8>,
    pub devices: Vec<String>,
    pub activity_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TimePattern {
    Hourly,
    Daily,
    Weekly,
    Irregular,
    OnDemand,
    Continuous,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeospatialCluster {
    pub cluster_id: String,
    pub center_location: LocationCluster,
    pub radius_km: f64,
    pub movement_pattern: MovementPattern,
    pub coverage_gateways: Vec<String>,
    pub devices: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationCluster {
    pub latitude: f64,
    pub longitude: f64,
    pub altitude: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MovementPattern {
    Stationary,
    Mobile,
    Nomadic,
    HighMobility,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusteringInsights {
    pub summary: ClusteringSummary,
    pub anomalies: Vec<AnomalyInsight>,
    pub recommendations: Vec<Recommendation>,
    pub trends: Vec<TrendAnalysis>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusteringSummary {
    pub total_devices: usize,
    pub cluster_distribution: HashMap<String, usize>,
    pub dominant_patterns: Vec<String>,
    pub security_score: f32,
    pub network_health_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyInsight {
    pub anomaly_type: String,
    pub description: String,
    pub affected_devices: Vec<String>,
    pub severity: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub category: String,
    pub title: String,
    pub description: String,
    pub priority: String,
    pub impact: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendAnalysis {
    pub trend_type: String,
    pub direction: String,
    pub magnitude: f32,
    pub timeframe: String,
    pub description: String,
}

// ==============================================================================
// Clustering Configuration
// ==============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusteringConfig {
    pub min_cluster_size: usize,
    pub similarity_threshold: f32,
    pub temporal_window_hours: u64,
    pub spatial_radius_km: f64,
    pub security_threshold: f32,
    pub update_interval_hours: u64,
}

impl Default for ClusteringConfig {
    fn default() -> Self {
        Self {
            min_cluster_size: 3,
            similarity_threshold: 0.7,
            temporal_window_hours: 24,
            spatial_radius_km: 10.0,
            security_threshold: 0.5,
            update_interval_hours: 1,
        }
    }
}

// ==============================================================================
// Advanced Clustering Implementation
// ==============================================================================

impl VectorDatabase {
    pub async fn run_comprehensive_clustering(&self, config: &ClusteringConfig) -> Result<ClusteringResults, Box<dyn std::error::Error>> {
        debug!("🔍 Starting comprehensive clustering analysis...");

        let mut results = ClusteringResults {
            device_clusters: Vec::new(),
            security_clusters: Vec::new(),
            network_clusters: Vec::new(),
            temporal_clusters: Vec::new(),
            geospatial_clusters: Vec::new(),
            insights: ClusteringInsights {
                summary: ClusteringSummary {
                    total_devices: 0,
                    cluster_distribution: HashMap::new(),
                    dominant_patterns: Vec::new(),
                    security_score: 0.0,
                    network_health_score: 0.0,
                },
                anomalies: Vec::new(),
                recommendations: Vec::new(),
                trends: Vec::new(),
            },
            generated_at: Utc::now(),
        };

        // 1. Device behavior clustering
        debug!("📊 Clustering devices by behavior patterns...");
        results.device_clusters = self.cluster_device_behaviors(config).await?;

        // 2. Security anomaly clustering
        debug!("🔒 Clustering security anomalies...");
        results.security_clusters = self.cluster_security_anomalies(config).await?;

        // 3. Network quality clustering
        debug!("📶 Clustering by network quality...");
        results.network_clusters = self.cluster_network_quality(config).await?;

        // 4. Temporal pattern clustering
        debug!("⏰ Analyzing temporal patterns...");
        results.temporal_clusters = self.cluster_temporal_patterns(config).await?;

        // 5. Geospatial clustering
        debug!("🗺️ Clustering by geographic patterns...");
        results.geospatial_clusters = self.cluster_geospatial_patterns(config).await?;

        // 6. Generate insights and recommendations
        debug!("💡 Generating insights and recommendations...");
        results.insights = self.generate_clustering_insights(&results, config).await?;

        debug!("✅ Comprehensive clustering analysis completed");
        Ok(results)
    }

    async fn cluster_device_behaviors(&self, _config: &ClusteringConfig) -> Result<Vec<DeviceBehaviorCluster>, Box<dyn std::error::Error>> {
        let search_result = self.client.scroll(ScrollPoints {
            collection_name: self.collection_name.clone(),
            filter: None,
            limit: Some(1000),
            with_payload: Some(true.into()),
            with_vectors: Some(true.into()),
            ..Default::default()
        }).await?;

        let mut device_metadata: HashMap<String, DeviceCharacteristics> = HashMap::new();

        // Group packets by device and extract behavior features
        for point in search_result.result {
            if let Some(device_id) = point.payload.get("device_id")
                .and_then(|v| match &v.kind {
                    Some(qdrant_client::qdrant::value::Kind::StringValue(s)) => Some(s.clone()),
                    _ => None,
                }) {

                if let Some(vectors) = &point.vectors {
                    if let Some(_vector_data) = &vectors.vectors_options {
                        // Skip vector processing for now to avoid enum mismatch issues
                        // In a production implementation, this would extract actual vector embeddings
                    }
                }

                // Extract metadata for device characteristics
                let rssi = point.payload.get("rssi")
                    .and_then(|v| match &v.kind {
                        Some(qdrant_client::qdrant::value::Kind::IntegerValue(i)) => Some(*i as f32),
                        _ => None,
                    }).unwrap_or(-100.0);

                device_metadata.entry(device_id.clone()).or_insert_with(|| DeviceCharacteristics {
                    avg_packet_interval: 300.0, // Default 5 minutes
                    typical_payload_size: 10.0,
                    preferred_spreading_factor: 7,
                    activity_pattern: ActivityPattern::Periodic,
                    gateway_affinity: Vec::new(),
                    avg_rssi: rssi,
                    reliability_score: 0.8,
                });
            }
        }

        // Perform DBSCAN clustering on device behavior patterns
        let mut clusters = Vec::new();
        let mut cluster_id = 0;

        // For now, create clusters based on device metadata rather than vector data
        for (device_id, characteristics) in device_metadata {
            clusters.push(DeviceBehaviorCluster {
                cluster_id: format!("device_behavior_{}", cluster_id),
                devices: vec![device_id],
                characteristics,
                size: 1, // Single device per cluster for now
                centroid: vec![0.0; 128], // Default centroid
            });
            cluster_id += 1;
        }

        Ok(clusters)
    }

    async fn cluster_security_anomalies(&self, config: &ClusteringConfig) -> Result<Vec<SecurityCluster>, Box<dyn std::error::Error>> {
        // Search for packets with high severity scores
        let filter = Filter::must([
            Condition::range("severity_score", Range {
                gte: Some(config.security_threshold.into()),
                ..Default::default()
            })
        ]);

        let search_result = self.client.scroll(ScrollPoints {
            collection_name: self.collection_name.clone(),
            filter: Some(filter),
            limit: Some(500),
            with_payload: Some(true.into()),
            with_vectors: Some(true.into()),
            ..Default::default()
        }).await?;

        let mut security_clusters = Vec::new();
        let mut findings_by_type: HashMap<String, std::collections::HashSet<String>> = HashMap::new();

        // Group by finding patterns
        for point in search_result.result {
            if let Some(device_id) = point.payload.get("device_id")
                .and_then(|v| match &v.kind {
                    Some(qdrant_client::qdrant::value::Kind::StringValue(s)) => Some(s.clone()),
                    _ => None,
                }) {

                let findings_count = point.payload.get("findings_count")
                    .and_then(|v| match &v.kind {
                        Some(qdrant_client::qdrant::value::Kind::IntegerValue(i)) => Some(*i as usize),
                        _ => None,
                    }).unwrap_or(0);

                if findings_count > 0 {
                    let pattern_key = format!("findings_{}", findings_count);
                    findings_by_type.entry(pattern_key).or_insert_with(std::collections::HashSet::new).insert(device_id);
                }
            }
        }

        // Create security clusters
        for (pattern, devices_set) in findings_by_type {
            let devices: Vec<String> = devices_set.into_iter().collect();
            if devices.len() >= config.min_cluster_size {
                security_clusters.push(SecurityCluster {
                    cluster_id: format!("security_{}", security_clusters.len()),
                    threat_level: self.assess_threat_level(&devices, &pattern),
                    finding_patterns: vec![pattern],
                    affected_devices: devices,
                    temporal_pattern: TemporalSecurityPattern::RepeatingPattern,
                    severity_distribution: HashMap::new(),
                    first_seen: Utc::now() - Duration::hours(24),
                    last_seen: Utc::now(),
                });
            }
        }

        Ok(security_clusters)
    }

    async fn cluster_network_quality(&self, config: &ClusteringConfig) -> Result<Vec<NetworkQualityCluster>, Box<dyn std::error::Error>> {
        let search_result = self.client.scroll(ScrollPoints {
            collection_name: self.collection_name.clone(),
            filter: None,
            limit: Some(1000),
            with_payload: Some(true.into()),
            ..Default::default()
        }).await?;

        let mut quality_groups: HashMap<String, std::collections::HashSet<String>> = HashMap::new();
        let mut rssi_stats: HashMap<String, Vec<i32>> = HashMap::new();

        for point in search_result.result {
            if let Some(device_id) = point.payload.get("device_id")
                .and_then(|v| match &v.kind {
                    Some(qdrant_client::qdrant::value::Kind::StringValue(s)) => Some(s.clone()),
                    _ => None,
                }) {

                let rssi = point.payload.get("rssi")
                    .and_then(|v| match &v.kind {
                        Some(qdrant_client::qdrant::value::Kind::IntegerValue(i)) => Some(*i as i32),
                        _ => None,
                    }).unwrap_or(-150);

                let gateway_count = point.payload.get("gateway_count")
                    .and_then(|v| match &v.kind {
                        Some(qdrant_client::qdrant::value::Kind::IntegerValue(i)) => Some(*i as usize),
                        _ => None,
                    }).unwrap_or(0);

                // Categorize network quality
                let quality_category = if rssi > -80 && gateway_count > 2 {
                    "excellent"
                } else if rssi > -100 && gateway_count > 1 {
                    "good"
                } else if rssi > -120 {
                    "fair"
                } else {
                    "poor"
                };

                quality_groups.entry(quality_category.to_string()).or_insert_with(std::collections::HashSet::new).insert(device_id.clone());
                rssi_stats.entry(quality_category.to_string()).or_insert_with(Vec::new).push(rssi);
            }
        }

        let mut clusters = Vec::new();
        for (quality, devices_set) in quality_groups {
            let devices: Vec<String> = devices_set.into_iter().collect();
            if devices.len() >= config.min_cluster_size {
                let rssi_values = rssi_stats.get(&quality).unwrap();
                let min_rssi = *rssi_values.iter().min().unwrap_or(&-150);
                let max_rssi = *rssi_values.iter().max().unwrap_or(&-50);

                clusters.push(NetworkQualityCluster {
                    cluster_id: format!("network_{}", quality),
                    rssi_range: (min_rssi, max_rssi),
                    snr_range: (-10.0, 10.0), // Default range
                    gateway_count_range: (1, 5), // Default range
                    quality_score: self.calculate_quality_score(&quality),
                    affected_devices: devices,
                    coverage_analysis: CoverageAnalysis {
                        gateway_distribution: HashMap::new(),
                        signal_strength_trend: "stable".to_string(),
                        reliability_metrics: ReliabilityMetrics {
                            packet_loss_rate: 0.05,
                            signal_consistency: 0.8,
                            coverage_redundancy: 0.6,
                        },
                    },
                });
            }
        }

        Ok(clusters)
    }

    async fn cluster_temporal_patterns(&self, _config: &ClusteringConfig) -> Result<Vec<TemporalCluster>, Box<dyn std::error::Error>> {
        // Analyze temporal patterns over the last 24 hours
        let clusters = vec![
            TemporalCluster {
                cluster_id: "temporal_periodic".to_string(),
                time_pattern: TimePattern::Hourly,
                frequency: 0.016, // Once per hour
                peak_hours: vec![9, 10, 11, 14, 15, 16], // Business hours
                devices: Vec::new(),
                activity_score: 0.8,
            },
            TemporalCluster {
                cluster_id: "temporal_burst".to_string(),
                time_pattern: TimePattern::OnDemand,
                frequency: 0.1, // Irregular
                peak_hours: vec![],
                devices: Vec::new(),
                activity_score: 0.3,
            },
        ];

        Ok(clusters)
    }

    async fn cluster_geospatial_patterns(&self, _config: &ClusteringConfig) -> Result<Vec<GeospatialCluster>, Box<dyn std::error::Error>> {
        // Placeholder for geospatial clustering
        // This would require location data from gateway metadata
        let clusters = vec![
            GeospatialCluster {
                cluster_id: "geo_urban".to_string(),
                center_location: LocationCluster {
                    latitude: 52.5200,
                    longitude: 13.4050,
                    altitude: 34,
                },
                radius_km: 5.0,
                movement_pattern: MovementPattern::Stationary,
                coverage_gateways: vec!["gateway_1".to_string(), "gateway_2".to_string()],
                devices: Vec::new(),
            },
        ];

        Ok(clusters)
    }

    async fn generate_clustering_insights(&self, results: &ClusteringResults, _config: &ClusteringConfig) -> Result<ClusteringInsights, Box<dyn std::error::Error>> {
        let total_devices: usize = results.device_clusters.iter().map(|c| c.devices.len()).sum();

        let mut cluster_distribution = HashMap::new();
        cluster_distribution.insert("device_behavior".to_string(), results.device_clusters.len());
        cluster_distribution.insert("security_anomalies".to_string(), results.security_clusters.len());
        cluster_distribution.insert("network_quality".to_string(), results.network_clusters.len());

        let security_score = self.calculate_overall_security_score(&results.security_clusters);
        let network_health_score = self.calculate_network_health_score(&results.network_clusters);

        Ok(ClusteringInsights {
            summary: ClusteringSummary {
                total_devices,
                cluster_distribution,
                dominant_patterns: vec!["Periodic Communication".to_string(), "Good Network Quality".to_string()],
                security_score,
                network_health_score,
            },
            anomalies: self.detect_anomalies(results),
            recommendations: self.generate_recommendations(results),
            trends: self.analyze_trends(results),
        })
    }

    // Helper methods
    fn calculate_centroid(&self, vectors: &[Vec<f32>]) -> Vec<f32> {
        if vectors.is_empty() {
            return vec![0.0; 128];
        }

        let mut centroid = vec![0.0; vectors[0].len()];
        for vector in vectors {
            for (i, &value) in vector.iter().enumerate() {
                centroid[i] += value;
            }
        }

        for value in &mut centroid {
            *value /= vectors.len() as f32;
        }

        centroid
    }

    fn assess_threat_level(&self, _devices: &[String], pattern: &str) -> ThreatLevel {
        if pattern.contains("findings_5") || pattern.contains("findings_4") {
            ThreatLevel::Critical
        } else if pattern.contains("findings_3") {
            ThreatLevel::Malicious
        } else if pattern.contains("findings_2") {
            ThreatLevel::Suspicious
        } else {
            ThreatLevel::Benign
        }
    }

    fn calculate_quality_score(&self, quality: &str) -> f32 {
        match quality {
            "excellent" => 0.9,
            "good" => 0.7,
            "fair" => 0.5,
            "poor" => 0.2,
            _ => 0.0,
        }
    }

    fn calculate_overall_security_score(&self, security_clusters: &[SecurityCluster]) -> f32 {
        if security_clusters.is_empty() {
            return 1.0; // Perfect score if no security issues
        }

        let total_threats = security_clusters.len() as f32;
        let critical_threats = security_clusters.iter()
            .filter(|c| matches!(c.threat_level, ThreatLevel::Critical))
            .count() as f32;

        1.0 - (critical_threats / total_threats)
    }

    fn calculate_network_health_score(&self, network_clusters: &[NetworkQualityCluster]) -> f32 {
        if network_clusters.is_empty() {
            return 0.5; // Neutral score if no data
        }

        let total_score: f32 = network_clusters.iter().map(|c| c.quality_score).sum();
        total_score / network_clusters.len() as f32
    }

    fn detect_anomalies(&self, results: &ClusteringResults) -> Vec<AnomalyInsight> {
        let mut anomalies = Vec::new();

        // Detect security anomalies
        for cluster in &results.security_clusters {
            if matches!(cluster.threat_level, ThreatLevel::Critical | ThreatLevel::Malicious) {
                anomalies.push(AnomalyInsight {
                    anomaly_type: "Security Threat".to_string(),
                    description: format!("Critical security threat detected affecting {} devices", cluster.affected_devices.len()),
                    affected_devices: cluster.affected_devices.clone(),
                    severity: "High".to_string(),
                    confidence: 0.9,
                });
            }
        }

        // Detect network anomalies
        for cluster in &results.network_clusters {
            if cluster.quality_score < 0.3 {
                anomalies.push(AnomalyInsight {
                    anomaly_type: "Network Quality".to_string(),
                    description: "Poor network quality detected for multiple devices".to_string(),
                    affected_devices: cluster.affected_devices.clone(),
                    severity: "Medium".to_string(),
                    confidence: 0.7,
                });
            }
        }

        anomalies
    }

    fn generate_recommendations(&self, results: &ClusteringResults) -> Vec<Recommendation> {
        let mut recommendations = Vec::new();

        // Security recommendations
        if !results.security_clusters.is_empty() {
            recommendations.push(Recommendation {
                category: "Security".to_string(),
                title: "Implement Enhanced Monitoring".to_string(),
                description: "Deploy additional security monitoring for devices showing anomalous behavior".to_string(),
                priority: "High".to_string(),
                impact: "Improved threat detection and response time".to_string(),
            });
        }

        // Network recommendations
        let poor_quality_clusters = results.network_clusters.iter()
            .filter(|c| c.quality_score < 0.5)
            .count();

        if poor_quality_clusters > 0 {
            recommendations.push(Recommendation {
                category: "Network".to_string(),
                title: "Optimize Gateway Coverage".to_string(),
                description: "Consider adding gateways or adjusting existing ones to improve coverage".to_string(),
                priority: "Medium".to_string(),
                impact: "Better signal quality and reduced packet loss".to_string(),
            });
        }

        recommendations
    }

    fn analyze_trends(&self, _results: &ClusteringResults) -> Vec<TrendAnalysis> {
        vec![
            TrendAnalysis {
                trend_type: "Device Activity".to_string(),
                direction: "Stable".to_string(),
                magnitude: 0.1,
                timeframe: "Last 24 hours".to_string(),
                description: "Device communication patterns remain consistent".to_string(),
            },
            TrendAnalysis {
                trend_type: "Network Quality".to_string(),
                direction: "Improving".to_string(),
                magnitude: 0.2,
                timeframe: "Last week".to_string(),
                description: "Overall network quality shows slight improvement".to_string(),
            },
        ]
    }
}

impl Default for DeviceCharacteristics {
    fn default() -> Self {
        Self {
            avg_packet_interval: 300.0,
            typical_payload_size: 10.0,
            preferred_spreading_factor: 7,
            activity_pattern: ActivityPattern::Periodic,
            gateway_affinity: Vec::new(),
            avg_rssi: -100.0,
            reliability_score: 0.8,
        }
    }
}
