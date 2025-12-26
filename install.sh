#!/bin/bash

echo "🚀 Installing Behavioral Anomaly Detection System..."
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "📦 Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    sudo usermod -aG docker $USER
    echo "✅ Docker installed"
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "📦 Installing Docker Compose..."
    sudo curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
    echo "✅ Docker Compose installed"
fi

# Build and start the system
echo ""
echo "🔨 Building anomaly detection system..."
docker-compose build

echo ""
echo "🚀 Starting system..."
docker-compose up -d

echo ""
echo "✅ Installation Complete!"
echo ""
echo "📊 Access dashboard at: http://localhost:5000"
echo ""
echo "📁 Drop CSV files in: ./data/incoming/"
echo ""
echo "Commands:"
echo "  View logs:    docker-compose logs -f"
echo "  Stop system:  docker-compose down"
echo "  Restart:      docker-compose restart"
echo ""
