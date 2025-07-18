use crate::vector_db::VectorDatabase;
use crate::dataset_processor::OfflinePacket;
use chrono::Utc;
use anyhow::Result;
use uuid::Uuid;

pub async fn test_data_persistence() -> Result<()> {
    println!("🔍 Testing data persistence...");

    // Test 1: Create vector database
    println!("1️⃣ Creating vector database...");
    let db = VectorDatabase::new("test_persistence").await?;
    println!("✅ Vector database created successfully");

    // Test 2: Create test data
    println!("2️⃣ Creating test data...");
    let test_packet = OfflinePacket {
        id: Uuid::new_v4().to_string(),
        device_id: "test-device-persistence".to_string(),
        timestamp: Utc::now(),
        frame_counter: Some(123),
        rssi: Some(-85),
        snr: Some(7.5),
        spreading_factor: Some(7),
        frequency: Some("868100000".to_string()),
        gateway_count: 2,
        payload: Some("48656C6C6F20576F726C64".to_string()),
        findings: vec![],
        source_file: "test_data.json".to_string(),
    };

    // Test 3: Store packet in database
    println!("3️⃣ Storing packet in database...");
    match db.store_packet(&test_packet).await {
        Ok(_) => println!("✅ Packet stored successfully"),
        Err(e) => println!("❌ Failed to store packet: {}", e),
    }

    // Test 4: Search for similar packets
    println!("4️⃣ Testing search functionality...");
    let query_embedding = vec![0.1; 128]; // Simple test embedding
    match db.search_similar_packets(query_embedding, 5, None).await {
        Ok(results) => {
            println!("✅ Search completed, found {} results", results.len());
            for result in results {
                println!("  - Device: {}, Timestamp: {}", result.device_id, result.timestamp);
            }
        }
        Err(e) => println!("❌ Search failed: {}", e),
    }

    // Test 5: Check anomalous packets
    println!("5️⃣ Testing anomaly detection...");
    match db.get_anomalous_packets(0.5, 10).await {
        Ok(anomalies) => {
            println!("✅ Anomaly detection completed, found {} anomalies", anomalies.len());
        }
        Err(e) => println!("❌ Anomaly detection failed: {}", e),
    }

    println!("🎉 Data persistence test completed!");
    Ok(())
}

pub async fn test_database() -> Result<()> {
    println!("Testing database connection...");

    // Test basic database operations
    match test_data_persistence().await {
        Ok(_) => println!("✅ Database tests passed"),
        Err(e) => println!("❌ Database tests failed: {}", e),
    }

    Ok(())
}
