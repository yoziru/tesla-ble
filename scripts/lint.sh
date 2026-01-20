#!/bin/bash
# Script to run clang-format and clang-tidy on the codebase

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "Running clang-format and clang-tidy checks..."

# Ensure we're in the project root
cd "$PROJECT_ROOT"

# Check if clang-format and clang-tidy are available
if ! command -v clang-format &> /dev/null; then
    echo "Error: clang-format not found. Please install clang-format."
    exit 1
fi

if ! command -v clang-tidy &> /dev/null; then
    echo "Error: clang-tidy not found. Please install clang-tidy."
    exit 1
fi

# Find all C++ source and header files
CPP_FILES=$(find src include tests examples -name "*.cpp" -o -name "*.h" | sort)

echo "Found $(echo "$CPP_FILES" | wc -l) C++ files to check"

# Check clang-format
echo "Checking clang-format..."
if echo "$CPP_FILES" | xargs clang-format --dry-run --Werror --style=file; then
    echo "✓ clang-format check passed"
else
    echo "✗ clang-format check failed. Run 'clang-format -i <files>' to fix formatting."
    exit 1
fi

# Check if build directory has compile_commands.json (needed for clang-tidy)
if [ ! -f "build/compile_commands.json" ]; then
    echo "compile_commands.json not found in build/. Running cmake configure..."
    if ! cmake -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -S . >/dev/null 2>&1; then
        echo "Error: Failed to configure CMake. Please run 'cmake -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON' manually first."
        exit 1
    fi
    echo "✓ CMake configured successfully"
fi

# Check clang-tidy (only on source files, not headers or tests for now)
SOURCE_FILES=$(find src -name "*.cpp" | sort)
echo "Running clang-tidy on $(echo "$SOURCE_FILES" | wc -l) source files..."
if echo "$SOURCE_FILES" | xargs clang-tidy -p build/ --header-filter="^(?!.*_deps).*" --quiet 2>&1 | grep -v "warnings generated"; then
    echo "✓ clang-tidy check passed"
else
    echo "✗ clang-tidy check failed. Fix the issues reported above."
    exit 1
fi

echo "All linting checks passed!"