#!/bin/bash
# Build and Pack Script for Argon2Sharp

set -e

# Resolve repository root (script is in deploy/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

echo "🔨 Building Argon2Sharp..."
echo ""

# Clean previous builds
echo "🧹 Cleaning previous builds..."
dotnet clean -c Release
rm -rf "$REPO_ROOT/src/Argon2Sharp/bin/Release"
rm -rf "$REPO_ROOT/src/Argon2Sharp/obj/Release"
rm -rf "$REPO_ROOT/artifacts"

# Restore dependencies
echo ""
echo "📦 Restoring dependencies..."
dotnet restore

# Build the project
echo ""
echo "🏗️  Building in Release mode..."
# Build solution (restored before)
dotnet build "$REPO_ROOT/Argon2Sharp.sln" -c Release --no-restore

# Run tests
echo ""
echo "🧪 Running tests..."
# Run tests (use the tests under test/)
dotnet test "$REPO_ROOT/test/Argon2Sharp.Tests/Argon2Sharp.Tests.csproj" -c Release --no-build --verbosity normal

# Create NuGet package
echo ""
echo "📦 Creating NuGet package..."
dotnet pack "$REPO_ROOT/src/Argon2Sharp/Argon2Sharp.csproj" -c Release --no-build --output "$REPO_ROOT/artifacts"

echo ""
echo "✅ Build completed successfully!"
echo ""
echo "📦 Package location: $REPO_ROOT/artifacts/"
ls -lh "$REPO_ROOT"/artifacts/*.nupkg 2>/dev/null || true
echo ""
echo "To publish to NuGet.org, run:"
echo "  dotnet nuget push \"$REPO_ROOT/artifacts/Argon2Sharp.*.nupkg\" --api-key YOUR_API_KEY --source https://api.nuget.org/v3/index.json"
