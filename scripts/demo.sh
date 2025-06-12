#!/bin/bash

# VOPRF Server Demo Script
echo "🚀 Starting VOPRF Server Demo"
echo "=============================="

# Start the server in the background
echo "📡 Starting VOPRF server..."
npm run dev &
SERVER_PID=$!

# Wait for server to start
echo "⏳ Waiting for server to initialize..."
sleep 5

# Check if server is running
if curl -s http://localhost:8001/ping > /dev/null; then
    echo "✅ Server is running!"
    
    # Run the client example
    echo "🔐 Running VOPRF client example..."
    npm run example:client
    
    echo "🎉 Demo completed!"
else
    echo "❌ Server failed to start"
fi

# Clean up - kill the server
echo "🧹 Cleaning up..."
kill $SERVER_PID 2>/dev/null

echo "👋 Demo finished" 