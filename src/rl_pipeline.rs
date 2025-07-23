use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use anyhow::Result;
use tracing::{info, debug};

/// State representation for LoRaWAN network optimization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkState {
    pub spreading_factor: u8,
    pub transmit_power: f32,
    pub data_rate: f32,
    pub channel_utilization: f32,
    pub packet_loss_rate: f32,
    pub energy_consumption: f32,
    pub network_congestion: f32,
    // New fields based on your plan
    pub rssi: f32,
    pub snr: f32,
    pub device_battery_level: f32, // 0.0 to 1.0
}

/// Action that can be taken to optimize the network
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum NetworkAction {
    IncreaseSF,
    DecreaseSF,
    IncreasePower,
    DecreasePower,
    ChangeChannel,
    NoAction,
}

/// RL Agent for network optimization
#[derive(Debug, Clone)]
pub struct LoRaWanRLAgent {
    pub q_table: HashMap<String, HashMap<NetworkAction, f32>>,
    pub learning_rate: f32,
    pub discount_factor: f32,
    pub epsilon: f32, // for epsilon-greedy exploration
    pub episodes_trained: u32,
}

impl LoRaWanRLAgent {
    pub fn new() -> Self {
        Self {
            q_table: HashMap::new(),
            learning_rate: 0.1,
            discount_factor: 0.95,
            epsilon: 0.1,
            episodes_trained: 0,
        }
    }

    /// Get state key for Q-table lookup
    pub fn get_state_key(&self, state: &NetworkState) -> String {
        format!(
            "SF:{}_TP:{:.1}_PLR:{:.2}_RSSI:{:.1}_SNR:{:.1}_BATT:{:.2}",
            state.spreading_factor,
            state.transmit_power,
            state.packet_loss_rate,
            state.rssi,
            state.snr,
            state.device_battery_level
        )
    }

    /// Select action using epsilon-greedy policy
    pub fn select_action(&self, state: &NetworkState) -> NetworkAction {
        let state_key = self.get_state_key(state);

        // Epsilon-greedy exploration
        if rand::random_f32() < self.epsilon {
            // Random action
            let actions = [
                NetworkAction::IncreaseSF,
                NetworkAction::DecreaseSF,
                NetworkAction::IncreasePower,
                NetworkAction::DecreasePower,
                NetworkAction::ChangeChannel,
                NetworkAction::NoAction,
            ];
            actions[rand::random_usize() % actions.len()]
        } else {
            // Greedy action
            if let Some(action_values) = self.q_table.get(&state_key) {
                action_values
                    .iter()
                    .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
                    .map(|(action, _)| *action)
                    .unwrap_or(NetworkAction::NoAction)
            } else {
                NetworkAction::NoAction
            }
        }
    }

    /// Update Q-value using Q-learning algorithm
    pub fn update_q_value(
        &mut self,
        state: &NetworkState,
        action: NetworkAction,
        reward: f32,
        next_state: &NetworkState,
    ) {
        let state_key = self.get_state_key(state);
        let next_state_key = self.get_state_key(next_state);

        // Initialize Q-values if not present
        self.q_table.entry(state_key.clone()).or_insert_with(HashMap::new);
        self.q_table.entry(next_state_key.clone()).or_insert_with(HashMap::new);

        // Get current Q-value
        let current_q = *self.q_table
            .get(&state_key)
            .unwrap()
            .get(&action)
            .unwrap_or(&0.0);

        // Get max Q-value for next state
        let max_next_q = self.q_table
            .get(&next_state_key)
            .map(|actions| {
                actions.values().fold(f32::NEG_INFINITY, |a, &b| a.max(b))
            })
            .unwrap_or(0.0);

        // Q-learning update
        let new_q = current_q + self.learning_rate * (reward + self.discount_factor * max_next_q - current_q);

        // Update Q-table
        self.q_table
            .get_mut(&state_key)
            .unwrap()
            .insert(action, new_q);
    }

    /// Train the agent with a single episode
    pub fn train_episode(&mut self, initial_state: NetworkState) -> Result<f32> {
        let mut current_state = initial_state;
        let mut total_reward = 0.0;
        let max_steps = 100;

        for step in 0..max_steps {
            // Select action
            let action = self.select_action(&current_state);

            // Simulate environment step
            let (next_state, reward) = self.simulate_environment_step(&current_state, action)?;

            // Update Q-value
            self.update_q_value(&current_state, action, reward, &next_state);

            total_reward += reward;
            current_state = next_state;

            // Check if episode should end
            if self.is_terminal_state(&current_state) || step == max_steps - 1 {
                break;
            }
        }

        self.episodes_trained += 1;
        Ok(total_reward)
    }

    /// Simulate environment step (simplified simulation)
    pub fn simulate_environment_step(&self, state: &NetworkState, action: NetworkAction) -> Result<(NetworkState, f32)> {
        let mut next_state = state.clone();
        let mut reward = 0.0;

        match action {
            NetworkAction::IncreaseSF => {
                if next_state.spreading_factor < 12 {
                    next_state.spreading_factor += 1;
                    next_state.packet_loss_rate *= 0.9; // Better reliability
                    next_state.energy_consumption *= 1.2; // Higher energy cost
                    next_state.rssi *= 0.98; // Slight improvement
                    next_state.snr += 0.5;
                    reward = 5.0 - (next_state.energy_consumption * 0.1);
                }
            }
            NetworkAction::DecreaseSF => {
                if next_state.spreading_factor > 7 {
                    next_state.spreading_factor -= 1;
                    next_state.packet_loss_rate *= 1.1; // Lower reliability
                    next_state.energy_consumption *= 0.8; // Lower energy cost
                    next_state.rssi *= 1.02;
                    next_state.snr -= 0.5;
                    reward = 3.0 - (next_state.packet_loss_rate * 10.0);
                }
            }
            NetworkAction::IncreasePower => {
                if next_state.transmit_power < 20.0 {
                    next_state.transmit_power += 1.0;
                    next_state.packet_loss_rate *= 0.95;
                    next_state.energy_consumption *= 1.1;
                    next_state.rssi += 1.0;
                    next_state.snr += 1.0;
                    reward = 2.0 - (next_state.energy_consumption * 0.05);
                }
            }
            NetworkAction::DecreasePower => {
                if next_state.transmit_power > 2.0 {
                    next_state.transmit_power -= 1.0;
                    next_state.packet_loss_rate *= 1.05;
                    next_state.energy_consumption *= 0.9;
                    next_state.rssi -= 1.0;
                    next_state.snr -= 1.0;
                    reward = 1.0 - (next_state.packet_loss_rate * 5.0);
                }
            }
            NetworkAction::ChangeChannel => {
                next_state.channel_utilization *= 0.8; // Less congestion
                next_state.network_congestion *= 0.7;
                reward = 4.0 - (next_state.network_congestion * 2.0);
            }
            NetworkAction::NoAction => {
                reward = -0.1; // Small negative reward for inaction
            }
        }

        // Add environmental noise
        next_state.channel_utilization += (rand::random_f32() - 0.5) * 0.1;
        next_state.network_congestion += (rand::random_f32() - 0.5) * 0.1;

        // Clamp values to valid ranges
        next_state.channel_utilization = next_state.channel_utilization.clamp(0.0, 1.0);
        next_state.network_congestion = next_state.network_congestion.clamp(0.0, 1.0);
        next_state.packet_loss_rate = next_state.packet_loss_rate.clamp(0.0, 1.0);
        next_state.rssi = next_state.rssi.clamp(-140.0, -30.0);
        next_state.snr = next_state.snr.clamp(-20.0, 10.0);

        Ok((next_state, reward))
    }

    /// Check if current state is terminal
    fn is_terminal_state(&self, state: &NetworkState) -> bool {
        state.packet_loss_rate > 0.5 || state.energy_consumption > 100.0
    }

    /// Get performance metrics
    pub fn get_performance_metrics(&self) -> HashMap<String, f32> {
        let mut metrics = HashMap::new();
        metrics.insert("episodes_trained".to_string(), self.episodes_trained as f32);
        metrics.insert("q_table_size".to_string(), self.q_table.len() as f32);

        let avg_q_value = self.q_table
            .values()
            .flat_map(|actions| actions.values())
            .sum::<f32>() / self.q_table.values().map(|actions| actions.len()).sum::<usize>() as f32;

        metrics.insert("avg_q_value".to_string(), avg_q_value);
        metrics
    }
}

/// RL Pipeline for LoRaWAN network optimization
pub struct RLPipeline {
    pub agent: LoRaWanRLAgent,
    pub training_data: Vec<NetworkState>,
    pub validation_data: Vec<NetworkState>,
}

impl RLPipeline {
    pub fn new() -> Self {
        Self {
            agent: LoRaWanRLAgent::new(),
            training_data: Vec::new(),
            validation_data: Vec::new(),
        }
    }

    /// Initialize with sample data
    pub fn initialize_with_sample_data(&mut self) -> Result<()> {
        info!("Initializing RL pipeline with sample data...");

        // Generate sample training data
        for i in 0..50 {
            let state = NetworkState {
                spreading_factor: 7 + (i % 6) as u8,
                transmit_power: 2.0 + (i % 19) as f32,
                data_rate: 0.3 + (i as f32 * 0.1) % 5.0,
                channel_utilization: (i as f32 * 0.02) % 1.0,
                packet_loss_rate: (i as f32 * 0.01) % 0.5,
                energy_consumption: 10.0 + (i as f32 * 0.5) % 50.0,
                network_congestion: (i as f32 * 0.015) % 1.0,
                rssi: -120.0 + (i as f32 * 1.5),
                snr: -15.0 + (i as f32 * 0.5),
                device_battery_level: (100.0 - (i as f32 * 0.5)).clamp(0.0, 100.0) / 100.0,
            };
            self.training_data.push(state);
        }

        // Generate sample validation data
        for i in 0..20 {
            let state = NetworkState {
                spreading_factor: 8 + (i % 5) as u8,
                transmit_power: 5.0 + (i % 15) as f32,
                data_rate: 1.0 + (i as f32 * 0.2) % 4.0,
                channel_utilization: (i as f32 * 0.03) % 1.0,
                packet_loss_rate: (i as f32 * 0.02) % 0.3,
                energy_consumption: 15.0 + (i as f32 * 0.8) % 40.0,
                network_congestion: (i as f32 * 0.025) % 1.0,
                rssi: -110.0 + (i as f32 * 2.0),
                snr: -10.0 + (i as f32 * 0.7),
                device_battery_level: (90.0 - (i as f32 * 1.0)).clamp(0.0, 100.0) / 100.0,
            };
            self.validation_data.push(state);
        }

        info!("Generated {} training samples and {} validation samples",
              self.training_data.len(), self.validation_data.len());
        Ok(())
    }

    /// Train the RL agent
    pub async fn train(&mut self, episodes: u32) -> Result<()> {
        info!("Starting RL training for {} episodes...", episodes);

        let mut total_rewards = Vec::new();

        for episode in 0..episodes {
            // Select random initial state from training data
            let initial_state = self.training_data[episode as usize % self.training_data.len()].clone();

            // Train episode
            let episode_reward = self.agent.train_episode(initial_state)?;
            total_rewards.push(episode_reward);

            if episode % 10 == 0 {
                let avg_reward = total_rewards.iter().sum::<f32>() / total_rewards.len() as f32;
                debug!("Episode {}: Average reward = {:.2}", episode, avg_reward);
            }
        }

        let final_avg_reward = total_rewards.iter().sum::<f32>() / total_rewards.len() as f32;
        info!("Training completed. Final average reward: {:.2}", final_avg_reward);

        Ok(())
    }

    /// Validate the trained agent
    pub async fn validate(&self) -> Result<HashMap<String, f32>> {
        info!("Validating trained RL agent...");

        let mut validation_rewards = Vec::new();
        let mut correct_actions = 0;
        let total_validations = self.validation_data.len();

        for state in &self.validation_data {
            let action = self.agent.select_action(state);
            let (_, reward) = self.agent.simulate_environment_step(state, action)?;
            validation_rewards.push(reward);

            // Check if action seems reasonable (basic heuristic)
            if self.is_action_reasonable(state, action) {
                correct_actions += 1;
            }
        }

        let avg_validation_reward = validation_rewards.iter().sum::<f32>() / validation_rewards.len() as f32;
        let action_accuracy = correct_actions as f32 / total_validations as f32;

        let mut metrics = HashMap::new();
        metrics.insert("avg_validation_reward".to_string(), avg_validation_reward);
        metrics.insert("action_accuracy".to_string(), action_accuracy);
        metrics.insert("total_validations".to_string(), total_validations as f32);

        info!("Validation completed. Average reward: {:.2}, Action accuracy: {:.2}%",
              avg_validation_reward, action_accuracy * 100.0);

        Ok(metrics)
    }

    /// Simple heuristic to check if action is reasonable
    fn is_action_reasonable(&self, state: &NetworkState, action: NetworkAction) -> bool {
        match action {
            NetworkAction::IncreaseSF => state.packet_loss_rate > 0.2,
            NetworkAction::DecreaseSF => state.energy_consumption > 80.0,
            NetworkAction::IncreasePower => state.packet_loss_rate > 0.3,
            NetworkAction::DecreasePower => state.energy_consumption > 90.0,
            NetworkAction::ChangeChannel => state.network_congestion > 0.7,
            NetworkAction::NoAction => state.packet_loss_rate < 0.1 && state.energy_consumption < 50.0,
        }
    }

    /// Get comprehensive pipeline metrics
    pub fn get_pipeline_metrics(&self) -> HashMap<String, f32> {
        let mut metrics = self.agent.get_performance_metrics();
        metrics.insert("training_samples".to_string(), self.training_data.len() as f32);
        metrics.insert("validation_samples".to_string(), self.validation_data.len() as f32);
        metrics
    }
}

// Add rand module for random number generation
mod rand {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};

    pub fn random_u64() -> u64 {
        let mut hasher = DefaultHasher::new();
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos().hash(&mut hasher);
        hasher.finish()
    }

    pub fn random_f32() -> f32 {
        (random_u64() % 10000) as f32 / 10000.0
    }

    pub fn random_usize() -> usize {
        random_u64() as usize
    }
}
