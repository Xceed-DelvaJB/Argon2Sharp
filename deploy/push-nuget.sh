#!/usr/bin/env bash
set -euo pipefail

# Simple deploy script to push NuGet package to nuget.org
# Requires NUGET_API_KEY to be set in environment

if [ -z "${NUGET_API_KEY:-}" ]; then
  echo "NUGET_API_KEY is not set. Export it and retry."
  exit 1
fi

PKG_PATH="./artifacts/Argon2Sharp.*.nupkg"

echo "Publishing packages matching: $PKG_PATH"

dotnet nuget push $PKG_PATH --api-key "$NUGET_API_KEY" --source https://api.nuget.org/v3/index.json --skip-duplicate

echo "Done."