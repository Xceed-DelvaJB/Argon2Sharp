# Build and Pack Script for Argon2Sharp
# PowerShell version

$ErrorActionPreference = "Stop"

Write-Host "🔨 Building Argon2Sharp..." -ForegroundColor Cyan
Write-Host ""

# Clean previous builds
Write-Host "🧹 Cleaning previous builds..." -ForegroundColor Yellow
dotnet clean -c Release
Remove-Item -Path "./Argon2Sharp/bin/Release" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "./Argon2Sharp/obj/Release" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "./artifacts" -Recurse -Force -ErrorAction SilentlyContinue

# Restore dependencies
Write-Host ""
Write-Host "📦 Restoring dependencies..." -ForegroundColor Yellow
dotnet restore

# Build the project
Write-Host ""
Write-Host "🏗️  Building in Release mode..." -ForegroundColor Yellow
# Build solution (projects moved to src/ and test/)
dotnet build Argon2Sharp.sln -c Release --no-restore

# Run tests
Write-Host ""
Write-Host "🧪 Running tests..." -ForegroundColor Yellow
# Run the test project now located under test/
dotnet test ./test/Argon2Sharp.Tests/Argon2Sharp.Tests.csproj -c Release --no-build --verbosity normal

# Create NuGet package
Write-Host ""
Write-Host "📦 Creating NuGet package..." -ForegroundColor Yellow
dotnet pack ./src/Argon2Sharp/Argon2Sharp.csproj -c Release --no-build --output ./artifacts

Write-Host ""
Write-Host "✅ Build completed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "📦 Package location: ./artifacts/" -ForegroundColor Cyan
Get-ChildItem ./artifacts/*.nupkg -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "   $($_.Name) ($([math]::Round($_.Length/1KB, 2)) KB)" }
Write-Host ""
Write-Host "To publish to NuGet.org, run:" -ForegroundColor Yellow
Write-Host "  dotnet nuget push ./artifacts/Argon2Sharp.*.nupkg --api-key YOUR_API_KEY --source https://api.nuget.org/v3/index.json" -ForegroundColor White
