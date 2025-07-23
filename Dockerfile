# Multi-stage build for LoRaWAN Dashboard
FROM rust:1.82-slim AS builder

# Install system dependencies needed for building
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy dependency files first for better caching
COPY Cargo.toml ./

# Create a dummy main.rs to build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies (this layer will be cached if Cargo.toml doesn't change)
RUN cargo build --release
RUN rm src/main.rs

# Copy the actual source code
COPY src/ ./src/

# Build the application
RUN touch src/main.rs && cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create app user for security
RUN useradd -r -s /bin/false -m -d /app lorawan

# Set working directory
WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/target/release/Pipeline /app/lorawan-dashboard

# Copy templates and static files
COPY templates/ ./templates/
COPY static/ ./static/

# Copy data files if they exist
COPY lorawan_dataset.json ./lorawan_dataset.json
COPY raw_data.json ./raw_data.json

# Change ownership to app user
RUN chown -R lorawan:lorawan /app

# Switch to non-root user
USER lorawan

# Expose the port the app runs on
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Set environment variables
ENV RUST_LOG=info
ENV BIND_ADDRESS=0.0.0.0:3000

# Run the application
CMD ["./lorawan-dashboard"]
