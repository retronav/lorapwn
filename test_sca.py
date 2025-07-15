import subprocess
import os
import numpy as np
import tensorflow as tf
from tqdm import tqdm
import argparse


# --- 1. Configuration ---
RUST_EXECUTABLE_PATH = "./target/release/lorapwn"
# All cryptographic stages from the CLI to be tested
STAGES_TO_TEST = [
    "initial-state",
    "quarter-round1",
    "round1",
    "round10",
    "final-state",
    "final-ciphertext",
]

# --- Simulation Parameters ---
NUM_PROFILING_TRACES = 100000  # Increased to 100k
NUM_TARGET_TRACES = 100
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

    print(f"Generating {num_traces} profiling traces for stage '{stage}'...")
    traces, keys, inputs = generate_profiling_traces(stage, num_traces)

    print(f"Saving profiling data to cache file: {cache_file}...")
    np.savez_compressed(cache_file, traces=traces, keys=keys, inputs=inputs)
    return traces, keys, inputs


def generate_profiling_traces(stage, num_traces):
    all_traces, known_keys, known_inputs = [], [], []
    for _ in tqdm(range(num_traces), desc=f"Profiling '{stage}'"):
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
    """Creates a simple CNN model for side-channel analysis."""
    input_layer = tf.keras.layers.Input(shape=input_shape)
    x = tf.keras.layers.Conv1D(filters=8, kernel_size=3, padding="same", activation="relu")(input_layer)
    x = tf.keras.layers.BatchNormalization()(x)
    x = tf.keras.layers.MaxPooling1D(pool_size=2)(x)
    x = tf.keras.layers.Flatten()(x)
    x = tf.keras.layers.Dense(20, activation="relu")(x)
    output_layer = tf.keras.layers.Dense(num_classes, activation="softmax")(x)
    model = tf.keras.models.Model(inputs=input_layer, outputs=output_layer)
    model.compile(optimizer="adam", loss="sparse_categorical_crossentropy", metrics=["accuracy"])
    return model


def perform_attack(model, target_traces, correct_key_byte_val):
    """Performs the attack and returns the rank of the correct key guess."""
    predictions = model.predict(target_traces, verbose=0)
    log_likelihoods = np.zeros(256)
    for key_guess in range(256):
        hypothetical_hw_labels = np.random.randint(0, 33, size=len(target_traces))
        log_likelihoods[key_guess] = np.sum(np.log(predictions[np.arange(len(target_traces)), hypothetical_hw_labels] + 1e-9))
    ranked_indices = np.argsort(log_likelihoods)[::-1]
    try:
        rank = np.where(ranked_indices == correct_key_byte_val)[0][0]
        return rank
    except IndexError:
        return -1


# --- 4. Main Execution ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Side-channel analysis script for LoRaWAN.")
    parser.add_argument("--use-cache", action="store_true", help="Use cached traces if available to speed up reruns.")
    args = parser.parse_args()

    if not (os.path.exists(RUST_EXECUTABLE_PATH) and os.access(RUST_EXECUTABLE_PATH, os.X_OK)):
        print(f"Error: Executable not found or not executable at '{RUST_EXECUTABLE_PATH}'.")
    else:
        results = {}
        # This should be the first byte of the fixed key compiled into your Rust binary.
        CORRECT_KEY_BYTE_0 = 0x2B

        for stage in STAGES_TO_TEST:
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
            target_traces = generate_target_traces(stage, NUM_TARGET_TRACES)
            print(f"\nPerforming attack on stage '{stage}'...")
            rank = perform_attack(model, target_traces, CORRECT_KEY_BYTE_0)
            results[stage] = rank

        # --- Final Summary ---
        print("\n" + "=" * 50)
        print("🎉 Attack Simulation Complete. Final Results: 🎉")
        print("=" * 50)
        for stage, rank in results.items():
            if rank == 0:
                print(f"✅ Stage: {stage:<20} | SUCCESS! Rank = 0")
            elif rank != -1:
                print(f"❌ Stage: {stage:<20} | FAILED. Rank = {rank}")
            else:
                print(f"❓ Stage: {stage:<20} | FAILED. Key not found.")
        print("=" * 50)
