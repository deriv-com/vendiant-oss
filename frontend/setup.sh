#!/bin/bash

# Vendiant Dashboard Frontend Setup Script

echo "🚀 Setting up Vendiant Dashboard Frontend..."

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js 18+ first."
    exit 1
fi

# Check Node.js version
NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 18 ]; then
    echo "❌ Node.js version 18+ is required. Current version: $(node -v)"
    exit 1
fi

echo "✅ Node.js $(node -v) detected"

# Clean install to avoid dependency conflicts
if [ -d "node_modules" ]; then
    echo "🧹 Cleaning existing node_modules..."
    rm -rf node_modules package-lock.json
fi

# Install dependencies
echo "📦 Installing dependencies..."
if command -v yarn &> /dev/null; then
    yarn install
else
    npm install
fi

# Fix security vulnerabilities
echo "🔒 Fixing security vulnerabilities..."
if command -v yarn &> /dev/null; then
    yarn audit --fix || echo "⚠️  Some vulnerabilities may require manual review"
else
    npm audit fix || echo "⚠️  Some vulnerabilities may require manual review"
fi

# Create environment file if it doesn't exist
if [ ! -f .env.local ]; then
    echo "📝 Creating .env.local file..."
    cat > .env.local << EOL
# Environment Variables
NEXT_PUBLIC_API_URL=http://localhost:5000
NODE_ENV=development
EOL
    echo "✅ Created .env.local with default settings"
else
    echo "✅ .env.local already exists"
fi

echo ""
echo "🎉 Setup complete!"
echo ""
echo "To start the development server:"
echo "  npm run dev"
echo "  # or"
echo "  yarn dev"
echo ""
echo "Then open http://localhost:3000 in your browser"
echo ""
echo "⚠️  Make sure your Flask backend is running on http://localhost:5000"
echo ""
echo "📋 Additional commands:"
echo "  npm run build    # Build for production"
echo "  npm run lint     # Run linting"
echo "  npm audit        # Check for vulnerabilities"
echo "" 