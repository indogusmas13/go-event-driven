#!/bin/bash

echo "Waiting for Kafka to be ready..."
sleep 10

echo "Creating topics..."

# Create user-events topic
/opt/kafka/bin/kafka-topics.sh --create \
    --bootstrap-server kafka:9092 \
    --topic user-events \
    --partitions 3 \
    --replication-factor 1 \
    --if-not-exists

echo "Topics created successfully"