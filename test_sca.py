import os
# Suppress TensorFlow warnings
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

import subprocess
import numpy as np
import tensorflow as tf
from tqdm import tqdm
import argparse


# --- 1. Configuration ---
RUST_EXECUTABLE_PATH = "./target/release/lorapwn"
# All cryptographic stages from the CLI to be tested
STAGES_TO_TEST = [
    "initial-state",
    "first-round",
    "round4",
    "round10",
    "final-state",
    "final-ciphertext",
]

# --- Simulation Parameters ---
NUM_PROFILING_TRACES = 100000  # Increased to 100k
NUM_TARGET_TRACES = 100
NUM_INFERENCE_RUNS = 10  # Number of times to repeat inference for better statistics
TRAINING_EPOCHS = 50  # Increased to 50
KEY_SIZE_BYTES = 32
INPUT_SIZE_BYTES = 12


# --- Helper Functions ---
def generate_hex_string(num_bytes):
    return os.urandom(num_bytes).hex()


def hamming_weight(n):
    return bin(n).count("1")


def run_rust_cli(mode, stage, input_data, key=None):
    command = [
        RUST_EXECUTABLE_PATH,
        "--mode",
        mode,
        "--stage",
        stage,
        "--input",
        input_data,
    ]
    if key:
        command.extend(["--key", key])

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return [int(val, 16) for val in result.stdout.strip().split()]
    except subprocess.CalledProcessError as e:
        print(f"Error running Rust CLI: {e}\nStderr: {e.stderr}")
        return None
    except FileNotFoundError:
        print(f"Error: Executable not found at '{RUST_EXECUTABLE_PATH}'")
        return None


# --- 2. Data Generation & Caching ---
def get_profiling_data(stage, num_traces, use_cache=False):
    cache_file = f"profiling_cache_{stage}_{num_traces}.npz"

    if use_cache and os.path.exists(cache_file):
        print(f"Loading cached profiling data for stage '{stage}' from {cache_file}...")
        cache = np.load(cache_file)
        return cache["traces"], cache["keys"], cache["inputs"]

    print(f"Generating {num_traces} profiling traces for stage '{stage}' using Rust CLI...")
    traces, keys, inputs = generate_profiling_traces_rust(stage, num_traces)

    print(f"Saving profiling data to cache file: {cache_file}...")
    np.savez_compressed(cache_file, traces=traces, keys=keys, inputs=inputs)
    return traces, keys, inputs


def generate_profiling_traces_rust(stage, num_traces):
    """Generate profiling traces using Rust CLI bulk mode for better performance."""
    command = [
        RUST_EXECUTABLE_PATH,
        "--mode", "bulk-profiling",
        "--stage", stage,
        "--num-traces", str(num_traces),
        "--verbose"
    ]

    try:
        print(f"Running: {' '.join(command)}")
        result = subprocess.run(command, capture_output=True, text=True, check=True)

        # Parse the CSV output: trace_hex,key_hex,input_hex
        lines = result.stdout.strip().split('\n')
        all_traces, known_keys, known_inputs = [], [], []

        for line in lines:
            if line.strip() and ',' in line:  # Skip empty lines and progress messages
                parts = line.split(',')
                if len(parts) == 3:
                    trace_hex, key_hex, input_hex = parts
                    # Convert hex trace to integer array
                    trace_bytes = bytes.fromhex(trace_hex)
                    trace_ints = [int.from_bytes(trace_bytes[i:i+4], 'little') for i in range(0, len(trace_bytes), 4)]

                    all_traces.append(trace_ints)
                    known_keys.append(key_hex)
                    known_inputs.append(input_hex)

        print(f"Successfully generated {len(all_traces)} traces using Rust CLI")
        return np.array(all_traces), np.array(known_keys), np.array(known_inputs)

    except subprocess.CalledProcessError as e:
        print(f"Error running Rust CLI bulk profiling: {e}")
        print(f"Stderr: {e.stderr}")
        print("Falling back to Python-based trace generation...")
        return generate_profiling_traces_python(stage, num_traces)
    except Exception as e:
        print(f"Error parsing Rust CLI output: {e}")
        print("Falling back to Python-based trace generation...")
        return generate_profiling_traces_python(stage, num_traces)


def generate_profiling_traces_python(stage, num_traces):
    """Fallback: Generate profiling traces using Python (slower but compatible)."""
    all_traces, known_keys, known_inputs = [], [], []
    for _ in tqdm(range(num_traces), desc=f"Profiling '{stage}' (Python fallback)"):
        key = generate_hex_string(KEY_SIZE_BYTES)
        input_data = generate_hex_string(INPUT_SIZE_BYTES)
        trace = run_rust_cli("profiling", stage, input_data, key=key)
        if trace:
            all_traces.append(trace)
            known_keys.append(key)
            known_inputs.append(input_data)
    return np.array(all_traces), np.array(known_keys), np.array(known_inputs)


def generate_target_traces(stage, num_traces):
    print(f"Generating {num_traces} target traces for stage '{stage}'...")
    all_traces = []
    for _ in tqdm(range(num_traces), desc=f"Attacking '{stage}'"):
        input_data = generate_hex_string(INPUT_SIZE_BYTES)
        trace = run_rust_cli("target", stage, input_data)
        if trace:
            all_traces.append(trace)
    return np.array(all_traces)


# --- 3. Analysis and Attack ---
def create_cnn_model(input_shape, num_classes):
    """Creates a CNN model for side-channel analysis."""
    input_layer = tf.keras.layers.Input(shape=input_shape)

    # Check if input is too small for pooling layers
    trace_length = input_shape[0]

    # --- Convolutional Blocks with adaptive pooling ---
    # Block 1
    x = tf.keras.layers.Conv1D(filters=8, kernel_size=3, padding="same")(input_layer)
    x = tf.keras.layers.BatchNormalization()(x)
    x = tf.keras.layers.ReLU()(x)
    if trace_length >= 4:  # Only pool if we have enough data
        x = tf.keras.layers.MaxPooling1D(pool_size=2)(x)
        trace_length = trace_length // 2
    x = tf.keras.layers.Dropout(0.1)(x)

    # Block 2
    x = tf.keras.layers.Conv1D(filters=16, kernel_size=3, padding="same")(x)
    x = tf.keras.layers.BatchNormalization()(x)
    x = tf.keras.layers.ReLU()(x)
    if trace_length >= 4:  # Only pool if we have enough data
        x = tf.keras.layers.MaxPooling1D(pool_size=2)(x)
        trace_length = trace_length // 2
    x = tf.keras.layers.Dropout(0.1)(x)

    # Block 3
    x = tf.keras.layers.Conv1D(filters=32, kernel_size=3, padding="same")(x)
    x = tf.keras.layers.BatchNormalization()(x)
    x = tf.keras.layers.ReLU()(x)
    if trace_length >= 4:  # Only pool if we have enough data
        x = tf.keras.layers.MaxPooling1D(pool_size=2)(x)
        trace_length = trace_length // 2
    x = tf.keras.layers.Dropout(0.1)(x)

    # Block 4
    x = tf.keras.layers.Conv1D(filters=64, kernel_size=3, padding="same")(x)
    x = tf.keras.layers.BatchNormalization()(x)
    x = tf.keras.layers.ReLU()(x)
    if trace_length >= 4:  # Only pool if we have enough data
        x = tf.keras.layers.MaxPooling1D(pool_size=2)(x)
        trace_length = trace_length // 2
    x = tf.keras.layers.Dropout(0.1)(x)

    # --- Fully Connected Layers ---
    x = tf.keras.layers.Flatten()(x)

    # Fully Connected Block 1
    x = tf.keras.layers.Dense(32, activation='relu')(x)
    x = tf.keras.layers.BatchNormalization()(x)
    x = tf.keras.layers.ReLU()(x)
    x = tf.keras.layers.Dropout(0.1)(x)

    # Fully Connected Block 2 (Output Layer)
    output_layer = tf.keras.layers.Dense(num_classes, activation="softmax")(x)

    model = tf.keras.models.Model(inputs=input_layer, outputs=output_layer)
    model.compile(optimizer="adam",
                  loss="sparse_categorical_crossentropy",
                  metrics=["accuracy"])
    return model


def perform_attack(model, target_traces, correct_key_byte_val, verbose=False):
    """Performs the attack and returns the rank of the correct key guess."""
    predictions = model.predict(target_traces, verbose=0)
    log_likelihoods = np.zeros(256)
    for key_guess in range(256):
        hypothetical_hw_labels = np.random.randint(0, 33, size=len(target_traces))
        log_likelihoods[key_guess] = np.sum(np.log(predictions[np.arange(len(target_traces)), hypothetical_hw_labels] + 1e-9))
    ranked_indices = np.argsort(log_likelihoods)[::-1]

    if verbose:
        print(f"  Target key byte: 0x{correct_key_byte_val:02X}")
        print(f"  Top 10 predicted keys:")
        for i in range(min(10, len(ranked_indices))):
            key_guess = ranked_indices[i]
            likelihood = log_likelihoods[key_guess]
            print(f"    Rank {i+1}: 0x{key_guess:02X} (likelihood: {likelihood:.4f})")

    try:
        rank = np.where(ranked_indices == correct_key_byte_val)[0][0]
        return rank, ranked_indices
    except IndexError:
        return -1, ranked_indices


def perform_multiple_attacks(model, stage, correct_key_byte_val, num_runs=NUM_INFERENCE_RUNS):
    """Performs multiple attacks and returns statistics."""
    ranks = []
    success_count = 0
    all_predictions = []

    print(f"Performing {num_runs} inference runs for stage '{stage}'...")
    print(f"Target key byte: 0x{correct_key_byte_val:02X}")
    print("-" * 40)

    for run in tqdm(range(num_runs), desc=f"Attacking '{stage}'"):
        # Generate fresh target traces for each run
        target_traces = generate_target_traces(stage, NUM_TARGET_TRACES)

        # Perform attack with verbose output for first few runs
        verbose = run < 3  # Show details for first 3 runs
        rank, ranked_indices = perform_attack(model, target_traces, correct_key_byte_val, verbose)

        ranks.append(rank)
        all_predictions.append(ranked_indices)

        if verbose:
            if rank == 0:
                print(f"  🎯 Run {run+1}: SUCCESS! Correct key ranked #1")
            elif rank != -1:
                print(f"  ❌ Run {run+1}: FAILED. Correct key ranked #{rank+1}")
            else:
                print(f"  ❓ Run {run+1}: FAILED. Correct key not found in ranking")
            print()

        if rank == 0:
            success_count += 1

    # Calculate statistics
    valid_ranks = [r for r in ranks if r != -1]
    stats = {
        'ranks': ranks,
        'success_count': success_count,
        'success_rate': success_count / num_runs,
        'avg_rank': np.mean(valid_ranks) if valid_ranks else -1,
        'median_rank': np.median(valid_ranks) if valid_ranks else -1,
        'min_rank': np.min(valid_ranks) if valid_ranks else -1,
        'max_rank': np.max(valid_ranks) if valid_ranks else -1,
        'failed_runs': num_runs - len(valid_ranks),
        'all_predictions': all_predictions
    }

    return stats


# --- 4. Main Execution ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Side-channel analysis script for LoRaWAN.")
    parser.add_argument("--use-cache", action="store_true", help="Use cached traces if available to speed up reruns.")
    parser.add_argument("--stage", choices=["all"] + STAGES_TO_TEST, default="first-round",
                        help="Stage to analyze (default: first-round).")
    parser.add_argument("--crypto", choices=["aead", "aes", "both"], default="both",
                        help="Cryptographic algorithm to analyze (default: both).")
    args = parser.parse_args()

    if not (os.path.exists(RUST_EXECUTABLE_PATH) and os.access(RUST_EXECUTABLE_PATH, os.X_OK)):
        print(f"Error: Executable not found or not executable at '{RUST_EXECUTABLE_PATH}'.")
    else:
        results = {}
        # This should be the first byte of the fixed key compiled into your Rust binary.
        CORRECT_KEY_BYTE_0 = 0x2B

        stages_to_analyze = STAGES_TO_TEST if args.stage == "all" else [args.stage]
        for stage in stages_to_analyze:
            print("-" * 50)
            print(f"🚀 Starting Analysis for Stage: {stage}")
            print("-" * 50)

            # --- Profiling & Training ---
            profiling_traces, _, _ = get_profiling_data(stage, NUM_PROFILING_TRACES, args.use_cache)
            profiling_labels = np.array([hamming_weight(trace[0]) for trace in profiling_traces])

            print(f"\nTraining model for '{stage}'...")
            trace_length = profiling_traces.shape[1]
            model = create_cnn_model(input_shape=(trace_length, 1), num_classes=33)
            model.fit(profiling_traces, profiling_labels, epochs=TRAINING_EPOCHS, batch_size=256, verbose=2)

            model_filename = f"model_{stage}.keras"
            print(f"Saving trained model to {model_filename}...")
            model.save(model_filename)

            # --- Attack Phase ---
            print(f"\nPerforming multiple attacks on stage '{stage}'...")
            attack_stats = perform_multiple_attacks(model, stage, CORRECT_KEY_BYTE_0, NUM_INFERENCE_RUNS)
            results[stage] = attack_stats

        # --- Final Summary ---
        print("\n" + "=" * 80)
        print("🎉 Attack Simulation Complete. Final Results: 🎉")
        print("=" * 80)
        for stage, stats in results.items():
            success_rate = stats['success_rate'] * 100
            avg_rank = stats['avg_rank']
            median_rank = stats['median_rank']
            min_rank = stats['min_rank']
            max_rank = stats['max_rank']
            failed_runs = stats['failed_runs']

            print(f"Stage: {stage:<20}")
            print(f"  Target Key Byte: 0x{CORRECT_KEY_BYTE_0:02X}")
            print(f"  Success Rate: {success_rate:.1f}% ({stats['success_count']}/{NUM_INFERENCE_RUNS})")
            if avg_rank != -1:
                print(f"  Average Rank: {avg_rank:.2f}")
                print(f"  Median Rank:  {median_rank:.1f}")
                print(f"  Min Rank:     {min_rank}")
                print(f"  Max Rank:     {max_rank}")
            if failed_runs > 0:
                print(f"  Failed Runs:  {failed_runs}")

            # Show top predicted keys across all runs
            all_predictions = stats['all_predictions']
            if all_predictions:
                # Count frequency of top predictions
                top_predictions = {}
                for predictions in all_predictions:
                    top_key = predictions[0]  # Best prediction for this run
                    top_predictions[top_key] = top_predictions.get(top_key, 0) + 1

                print(f"  Most Frequent Top Predictions:")
                sorted_predictions = sorted(top_predictions.items(), key=lambda x: x[1], reverse=True)
                for i, (key, count) in enumerate(sorted_predictions[:5]):
                    percentage = (count / NUM_INFERENCE_RUNS) * 100
                    marker = "🎯" if key == CORRECT_KEY_BYTE_0 else "  "
                    print(f"    {marker} 0x{key:02X}: {count}/{NUM_INFERENCE_RUNS} runs ({percentage:.1f}%)")

            if stats['success_count'] > 0:
                print(f"  ✅ SUCCESS! ({stats['success_count']}/{NUM_INFERENCE_RUNS} runs)")
            else:
                print(f"  ❌ FAILED. No successful attacks.")
            print()
        print("=" * 80)
