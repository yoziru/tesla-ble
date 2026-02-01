#!/bin/sh
# Script to run clang-format checks and fixes
# Platform-independent - works on Linux and macOS

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# Default mode
CHECK_MODE=0

# Parse arguments
for arg in "$@"; do
    case $arg in
        --check)
            CHECK_MODE=1
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--check]"
            echo ""
            echo "Options:"
            echo "  --check    Dry run mode for CI (checks without modifying files)"
            echo "  --help     Show this help message"
            echo ""
            echo "Without --check, formats all files in-place."
            echo "With --check, verifies formatting without modifying files."
            exit 0
            ;;
    esac
done

# Check if clang-format is available
if ! command -v clang-format >/dev/null 2>&1; then
    echo "Error: clang-format not found. Please install clang-format."
    exit 1
fi

# Find all C++ source and header files
cd "$ROOT_DIR"
CPP_FILES=$(find src include tests examples -name "*.cpp" -o -name "*.h" | sort)

if [ -z "$CPP_FILES" ]; then
    echo "No C++ files found to check"
    exit 0
fi

FILE_COUNT=$(echo "$CPP_FILES" | wc -l | tr -d ' ')
echo "Found $FILE_COUNT C++ files to process"

if [ $CHECK_MODE -eq 1 ]; then
    echo "Running clang-format check (dry-run mode)..."
    if echo "$CPP_FILES" | xargs clang-format --dry-run --Werror --style=file; then
        echo "✓ clang-format check passed"
        exit 0
    else
        echo "✗ clang-format check failed. Run '$0' to fix formatting."
        exit 1
    fi
else
    echo "Running clang-format (fix mode)..."
    echo "$CPP_FILES" | xargs clang-format -i --style=file
    echo "✓ clang-format completed - files have been formatted"
    exit 0
fi
