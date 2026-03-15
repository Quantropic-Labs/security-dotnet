#!/bin/bash
set -e

TARGET="${1:-Build}"
CONFIGURATION="${2:-Release}"
OUTPUT_PATH="./artifacts"

# Исправлено: только ОДИН уровень вверх
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo -e "\033[0;36m=== Quantropic Security Build ===\033[0m"
echo -e "\033[1;33mTarget: $TARGET | Configuration: $CONFIGURATION\033[0m"
echo -e "\033[0;90mLocation: $(pwd)\033[0m"
echo ""

clean() {
    echo -e "\033[0;32m=== Cleaning... ===\033[0m"
    rm -rf "$OUTPUT_PATH"
    find . -type d -name "bin" -exec rm -rf {} + 2>/dev/null || true
    find . -type d -name "obj" -exec rm -rf {} + 2>/dev/null || true
    echo -e "\033[0;32mClean completed\033[0m"
}

build() {
    echo -e "\033[0;32m=== Building... ===\033[0m"
    dotnet restore Quantropic.Security.slnx
    dotnet build Quantropic.Security.slnx --configuration "$CONFIGURATION" --no-restore
    echo -e "\033[0;32mBuild completed\033[0m"
}

test() {
    echo -e "\033[0;32m=== Running tests... ===\033[0m"
    dotnet test Quantropic.Security.slnx --configuration "$CONFIGURATION" --no-build --verbosity normal
    echo -e "\033[0;32mTests completed\033[0m"
}

pack() {
    echo -e "\033[0;32m=== Packing NuGet packages (local)... ===\033[0m"
    mkdir -p "$OUTPUT_PATH/nuget"
    dotnet pack Quantropic.Security.slnx --configuration "$CONFIGURATION" --output "$OUTPUT_PATH/nuget"
    echo -e "\033[0;32mPackages created in $OUTPUT_PATH/nuget\033[0m"
}

case "$TARGET" in
    "Clean") clean ;;
    "Build") clean; build ;;
    "Test") build; test ;;
    "Pack") build; pack ;;
    "All") clean; build; test; pack ;;
    *) echo "Unknown target: $TARGET"; exit 1 ;;
esac

echo -e "\n\033[0;36m=== Done ===\033[0m"