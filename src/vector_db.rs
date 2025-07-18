use qdrant_client::{
    client::QdrantClient,
    qdrant::{
        CreateCollection, Distance, VectorParams, PointStruct, SearchPoints,
        VectorsConfig, Value as QdrantValue, Condition, Range, Filter,
    },
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
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
    client: QdrantClient,
    collection_name: String,
}

// Manually implement Debug since QdrantClient doesn't implement it
impl std::fmt::Debug for VectorDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VectorDatabase")
            .field("collection_name", &self.collection_name)
            .field("client", &"QdrantClient(...)".to_string())
            .finish()
    }
}

impl VectorDatabase {
    pub async fn new(collection_name: &str) -> Result<Self> {
        let client = QdrantClient::new(None)?;

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
                .create_collection(&CreateCollection {
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

        self.client.upsert_points(
            &self.collection_name,
            None,
            vec![point],
            None
        ).await?;

        debug!("Stored packet {} in vector database", packet.get_id());
        Ok(())
    }

    pub async fn search_similar_packets(
        &self,
        query_embedding: Vec<f32>,
        limit: usize,
        filter: Option<Filter>,
    ) -> Result<Vec<PacketEmbedding>, Box<dyn std::error::Error>> {
        let search_result = self.client.search_points(&SearchPoints {
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

        let search_result = self.client.scroll(&qdrant_client::qdrant::ScrollPoints {
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
