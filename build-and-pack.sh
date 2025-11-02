#!/bin/bash
# Build and Pack Script for Argon2Sharp

set -e

echo "🔨 Building Argon2Sharp..."
echo ""

# Clean previous builds
echo "🧹 Cleaning previous builds..."
dotnet clean -c Release
rm -rf ./Argon2Sharp/bin/Release
rm -rf ./Argon2Sharp/obj/Release
rm -rf ./artifacts

# Restore dependencies
echo ""
echo "📦 Restoring dependencies..."
dotnet restore

# Build the project
echo ""
echo "🏗️  Building in Release mode..."
dotnet build -c Release --no-restore

# Run tests
echo ""
echo "🧪 Running tests..."
dotnet test -c Release --no-build --verbosity normal

# Create NuGet package
echo ""
echo "📦 Creating NuGet package..."
dotnet pack ./Argon2Sharp/Argon2Sharp.csproj -c Release --no-build --output ./artifacts

echo ""
echo "✅ Build completed successfully!"
echo ""
echo "📦 Package location: ./artifacts/"
ls -lh ./artifacts/*.nupkg 2>/dev/null || true
echo ""
echo "To publish to NuGet.org, run:"
echo "  dotnet nuget push ./artifacts/Argon2Sharp.*.nupkg --api-key YOUR_API_KEY --source https://api.nuget.org/v3/index.json"
