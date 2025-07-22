use crate::rl_pipeline::{RLPipeline, LoRaWanRLAgent, NetworkState, NetworkAction};
use anyhow::Result;
use tracing::{info, debug};
use std::collections::HashMap;

/// Main test function for the reinforcement learning pipeline
pub async fn test_reinforcement_learning() -> Result<()> {
    info!("🤖 Starting Reinforcement Learning Pipeline Tests...");

    // Test 1: Basic RL Agent functionality
    test_rl_agent_basic_functionality().await?;

    // Test 2: Q-learning algorithm
    test_q_learning_algorithm().await?;

    // Test 3: Network state management
    test_network_state_management().await?;

    // Test 4: Action selection
    test_action_selection().await?;

    // Test 5: Environment simulation
    test_environment_simulation().await?;

    // Test 6: Full pipeline training
    test_full_pipeline_training().await?;

    // Test 7: Pipeline validation
    test_pipeline_validation().await?;

    // Test 8: Performance metrics
    test_performance_metrics().await?;

    info!("✅ All RL pipeline tests completed successfully!");
    Ok(())
}

/// Test basic RL agent functionality
async fn test_rl_agent_basic_functionality() -> Result<()> {
    info!("Testing basic RL agent functionality...");

    let agent = LoRaWanRLAgent::new();

    // Test initial state
    assert_eq!(agent.episodes_trained, 0);
    assert_eq!(agent.learning_rate, 0.1);
    assert_eq!(agent.discount_factor, 0.95);
    assert_eq!(agent.epsilon, 0.1);
    assert!(agent.q_table.is_empty());

    info!("✅ Basic RL agent functionality test passed");
    Ok(())
}

/// Test Q-learning algorithm implementation
async fn test_q_learning_algorithm() -> Result<()> {
    info!("Testing Q-learning algorithm...");

    let mut agent = LoRaWanRLAgent::new();

    // Create test states
    let state1 = NetworkState {
        spreading_factor: 7,
        transmit_power: 14.0,
        data_rate: 5.0,
        channel_utilization: 0.3,
        packet_loss_rate: 0.1,
        energy_consumption: 20.0,
        network_congestion: 0.2,
    };

    let state2 = NetworkState {
        spreading_factor: 8,
        transmit_power: 14.0,
        data_rate: 4.0,
        channel_utilization: 0.4,
        packet_loss_rate: 0.05,
        energy_consumption: 25.0,
        network_congestion: 0.3,
    };

    let action = NetworkAction::IncreaseSF;
    let reward = 5.0;

    // Test Q-value update
    agent.update_q_value(&state1, action, reward, &state2);

    // Check that Q-table was updated
    assert!(!agent.q_table.is_empty());

    // Test multiple updates
    for i in 0..10 {
        agent.update_q_value(&state1, action, reward + i as f32, &state2);
    }

    info!("✅ Q-learning algorithm test passed");
    Ok(())
}

/// Test network state management
async fn test_network_state_management() -> Result<()> {
    info!("Testing network state management...");

    let agent = LoRaWanRLAgent::new();

    // Create various network states
    let states = vec![
        NetworkState {
            spreading_factor: 7,
            transmit_power: 2.0,
            data_rate: 5.0,
            channel_utilization: 0.1,
            packet_loss_rate: 0.05,
            energy_consumption: 15.0,
            network_congestion: 0.1,
        },
        NetworkState {
            spreading_factor: 12,
            transmit_power: 20.0,
            data_rate: 0.3,
            channel_utilization: 0.9,
            packet_loss_rate: 0.4,
            energy_consumption: 95.0,
            network_congestion: 0.8,
        },
    ];

    // Test state key generation
    for state in &states {
        let key = agent.get_state_key(state);
        assert!(!key.is_empty());
        debug!("State key generated: {}", key);
    }

    // Test state validation
    for state in &states {
        assert!(state.spreading_factor >= 7 && state.spreading_factor <= 12);
        assert!(state.transmit_power >= 0.0 && state.transmit_power <= 20.0);
        assert!(state.channel_utilization >= 0.0 && state.channel_utilization <= 1.0);
        assert!(state.packet_loss_rate >= 0.0 && state.packet_loss_rate <= 1.0);
        assert!(state.network_congestion >= 0.0 && state.network_congestion <= 1.0);
    }

    info!("✅ Network state management test passed");
    Ok(())
}

/// Test action selection mechanisms
async fn test_action_selection() -> Result<()> {
    info!("Testing action selection mechanisms...");

    let mut agent = LoRaWanRLAgent::new();

    let test_state = NetworkState {
        spreading_factor: 9,
        transmit_power: 10.0,
        data_rate: 2.0,
        channel_utilization: 0.5,
        packet_loss_rate: 0.2,
        energy_consumption: 50.0,
        network_congestion: 0.4,
    };

    // Test action selection with empty Q-table (should return NoAction or random)
    let action1 = agent.select_action(&test_state);
    debug!("Selected action with empty Q-table: {:?}", action1);

    // Train agent with some data
    agent.update_q_value(&test_state, NetworkAction::IncreaseSF, 10.0, &test_state);
    agent.update_q_value(&test_state, NetworkAction::DecreasePower, 5.0, &test_state);

    // Test action selection with trained Q-table
    let action2 = agent.select_action(&test_state);
    debug!("Selected action with trained Q-table: {:?}", action2);

    // Test multiple action selections
    let mut action_counts = HashMap::new();
    for _ in 0..100 {
        let action = agent.select_action(&test_state);
        *action_counts.entry(format!("{:?}", action)).or_insert(0) += 1;
    }

    debug!("Action distribution: {:?}", action_counts);

    info!("✅ Action selection test passed");
    Ok(())
}

/// Test environment simulation
async fn test_environment_simulation() -> Result<()> {
    info!("Testing environment simulation...");

    let agent = LoRaWanRLAgent::new();

    let initial_state = NetworkState {
        spreading_factor: 8,
        transmit_power: 12.0,
        data_rate: 3.0,
        channel_utilization: 0.6,
        packet_loss_rate: 0.3,
        energy_consumption: 40.0,
        network_congestion: 0.5,
    };

    // Test different actions
    let actions = [
        NetworkAction::IncreaseSF,
        NetworkAction::DecreaseSF,
        NetworkAction::IncreasePower,
        NetworkAction::DecreasePower,
        NetworkAction::ChangeChannel,
        NetworkAction::NoAction,
    ];

    for action in &actions {
        let (next_state, reward) = agent.simulate_environment_step(&initial_state, *action)?;

        // Validate next state
        assert!(next_state.spreading_factor >= 7 && next_state.spreading_factor <= 12);
        assert!(next_state.transmit_power >= 0.0 && next_state.transmit_power <= 25.0);
        assert!(next_state.channel_utilization >= 0.0 && next_state.channel_utilization <= 1.0);
        assert!(next_state.packet_loss_rate >= 0.0 && next_state.packet_loss_rate <= 1.0);
        assert!(next_state.network_congestion >= 0.0 && next_state.network_congestion <= 1.0);

        debug!("Action: {:?}, Reward: {:.2}", action, reward);
    }

    info!("✅ Environment simulation test passed");
    Ok(())
}

/// Test full pipeline training
async fn test_full_pipeline_training() -> Result<()> {
    info!("Testing full pipeline training...");

    let mut pipeline = RLPipeline::new();

    // Initialize with sample data
    pipeline.initialize_with_sample_data()?;

    // Verify data initialization
    assert!(!pipeline.training_data.is_empty());
    assert!(!pipeline.validation_data.is_empty());

    debug!("Training data samples: {}", pipeline.training_data.len());
    debug!("Validation data samples: {}", pipeline.validation_data.len());

    // Train for a small number of episodes
    let episodes = 20;
    pipeline.train(episodes).await?;

    // Verify training occurred
    assert_eq!(pipeline.agent.episodes_trained, episodes);
    assert!(!pipeline.agent.q_table.is_empty());

    info!("✅ Full pipeline training test passed");
    Ok(())
}

/// Test pipeline validation
async fn test_pipeline_validation() -> Result<()> {
    info!("Testing pipeline validation...");

    let mut pipeline = RLPipeline::new();

    // Initialize and train
    pipeline.initialize_with_sample_data()?;
    pipeline.train(10).await?;

    // Validate the trained agent
    let validation_metrics = pipeline.validate().await?;

    // Check validation metrics
    assert!(validation_metrics.contains_key("avg_validation_reward"));
    assert!(validation_metrics.contains_key("action_accuracy"));
    assert!(validation_metrics.contains_key("total_validations"));

    let avg_reward = validation_metrics.get("avg_validation_reward").unwrap();
    let accuracy = validation_metrics.get("action_accuracy").unwrap();
    let total_validations = validation_metrics.get("total_validations").unwrap();

    debug!("Validation metrics:");
    debug!("  Average reward: {:.2}", avg_reward);
    debug!("  Action accuracy: {:.2}%", accuracy * 100.0);
    debug!("  Total validations: {}", total_validations);

    // Basic sanity checks
    assert!(*accuracy >= 0.0 && *accuracy <= 1.0);
    assert!(*total_validations > 0.0);

    info!("✅ Pipeline validation test passed");
    Ok(())
}

/// Test performance metrics collection
async fn test_performance_metrics() -> Result<()> {
    info!("Testing performance metrics collection...");

    let mut pipeline = RLPipeline::new();

    // Initialize and train
    pipeline.initialize_with_sample_data()?;
    pipeline.train(15).await?;

    // Get agent metrics
    let agent_metrics = pipeline.agent.get_performance_metrics();
    assert!(agent_metrics.contains_key("episodes_trained"));
    assert!(agent_metrics.contains_key("q_table_size"));
    assert!(agent_metrics.contains_key("avg_q_value"));

    // Get pipeline metrics
    let pipeline_metrics = pipeline.get_pipeline_metrics();
    assert!(pipeline_metrics.contains_key("training_samples"));
    assert!(pipeline_metrics.contains_key("validation_samples"));

    debug!("Agent metrics: {:?}", agent_metrics);
    debug!("Pipeline metrics: {:?}", pipeline_metrics);

    // Validate metrics values
    let episodes_trained = agent_metrics.get("episodes_trained").unwrap();
    let q_table_size = agent_metrics.get("q_table_size").unwrap();

    assert_eq!(*episodes_trained, 15.0);
    assert!(*q_table_size > 0.0);

    info!("✅ Performance metrics test passed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rl_agent_creation() {
        let agent = LoRaWanRLAgent::new();
        assert_eq!(agent.episodes_trained, 0);
        assert!(agent.q_table.is_empty());
    }

    #[tokio::test]
    async fn test_pipeline_initialization() {
        let mut pipeline = RLPipeline::new();
        pipeline.initialize_with_sample_data().unwrap();
        assert!(!pipeline.training_data.is_empty());
        assert!(!pipeline.validation_data.is_empty());
    }

    #[tokio::test]
    async fn test_network_state_creation() {
        let state = NetworkState {
            spreading_factor: 9,
            transmit_power: 15.0,
            data_rate: 2.5,
            channel_utilization: 0.7,
            packet_loss_rate: 0.15,
            energy_consumption: 45.0,
            network_congestion: 0.6,
        };

        assert_eq!(state.spreading_factor, 9);
        assert_eq!(state.transmit_power, 15.0);
    }
}
