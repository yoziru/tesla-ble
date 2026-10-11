#!/bin/sh
# Script to run clang-tidy checks and fixes
# Platform-independent - works on Linux and macOS

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# Default mode
CHECK_MODE=0
FIX_MODE=0

# Parse arguments
for arg in "$@"; do
    case $arg in
        --check)
            CHECK_MODE=1
            shift
            ;;
        --fix)
            FIX_MODE=1
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--check] [--fix]"
            echo ""
            echo "Options:"
            echo "  --check    Dry run mode for CI (checks without modifying files)"
            echo "  --fix      Apply automatic fixes where possible"
            echo "  --help     Show this help message"
            echo ""
            echo "Without --check: runs clang-tidy and reports issues."
            echo "With --check: runs clang-tidy and exits with error if issues found."
            echo "With --fix: attempts to apply automatic fixes."
            exit 0
            ;;
    esac
done

# Check if clang-tidy is available
if ! command -v clang-tidy >/dev/null 2>&1; then
    echo "Error: clang-tidy not found. Please install clang-tidy."
    exit 1
fi

cd "$ROOT_DIR"

# Check if build directory has compile_commands.json (needed for clang-tidy)
if [ ! -f "build/compile_commands.json" ]; then
    echo "compile_commands.json not found in build/. Running cmake configure..."
    if ! cmake -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -S . -DCMAKE_MESSAGE_LOG_LEVEL=ERROR >/dev/null 2>&1; then
        echo "Error: Failed to configure CMake. Please run 'cmake -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON' manually first."
        exit 1
    fi
    echo "✓ CMake configured successfully"
fi

# Find source files (excluding generated and deps)
SOURCE_FILES=$(find src -name "*.cpp" | grep -v "generated/" | grep -v "_deps/" | sort)

# Python bindings use a separate compile database (pybind11 include paths).
BINDINGS_FILES=$(find bindings/python/cpp -name "*.cpp" 2>/dev/null | sort)
BINDINGS_BUILD_DIR="build-bindings"
BINDINGS_PYTHON="$ROOT_DIR/.venv/bin/python"

if [ -n "$BINDINGS_FILES" ]; then
    if [ ! -f "$BINDINGS_BUILD_DIR/compile_commands.json" ]; then
        if [ -x "$BINDINGS_PYTHON" ] && "$BINDINGS_PYTHON" -c "import pybind11" >/dev/null 2>&1; then
            echo "Configuring bindings build for clang-tidy (build-bindings/)..."
            PYBIND11_DIR=$("$BINDINGS_PYTHON" -m pybind11 --cmakedir)
            cmake -S bindings/python -B "$BINDINGS_BUILD_DIR" \
                -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_BUILD_TYPE=Release \
                -Dpybind11_DIR="$PYBIND11_DIR" -DPython_EXECUTABLE="$BINDINGS_PYTHON" \
                -DCMAKE_MESSAGE_LOG_LEVEL=ERROR >/dev/null 2>&1 || {
                if [ "$CHECK_MODE" -eq 1 ]; then
                    echo "Error: Failed to configure bindings build for clang-tidy"
                    exit 1
                fi
                echo "Warning: could not configure bindings build; skipping bindings clang-tidy"
                BINDINGS_FILES=""
            }
        else
            echo "Note: .venv with pybind11 not found (run 'uv sync'); skipping bindings clang-tidy"
            BINDINGS_FILES=""
        fi
    fi
fi

if [ -z "$SOURCE_FILES" ] && [ -z "$BINDINGS_FILES" ]; then
    echo "No source files found to check"
    exit 0
fi

FILE_COUNT=$(echo "$SOURCE_FILES $BINDINGS_FILES" | wc -w | tr -d ' ')
echo "Running clang-tidy on $FILE_COUNT source files..."

# Determine number of parallel jobs
# Use nproc on Linux, sysctl on macOS, or default to 4
if command -v nproc >/dev/null 2>&1; then
    JOBS=$(nproc)
elif command -v sysctl >/dev/null 2>&1; then
    JOBS=$(sysctl -n hw.ncpu 2>/dev/null || echo 4)
else
    JOBS=4
fi

# Build clang-tidy arguments
TIDY_ARGS="--config-file=.clang-tidy --quiet"

if [ $FIX_MODE -eq 1 ]; then
    TIDY_ARGS="$TIDY_ARGS --fix"
    echo "Fix mode enabled - will attempt to apply automatic fixes"
fi

# Run clang-tidy for the library and, when available, the Python bindings.
run_tidy() {
    if [ -n "$SOURCE_FILES" ]; then
        echo "$SOURCE_FILES" | xargs -P "$JOBS" clang-tidy $TIDY_ARGS -p build/
    fi
    if [ -n "$BINDINGS_FILES" ]; then
        echo "$BINDINGS_FILES" | xargs -P "$JOBS" clang-tidy $TIDY_ARGS -p "$BINDINGS_BUILD_DIR"
    fi
}

# Run clang-tidy
if [ $CHECK_MODE -eq 1 ]; then
    # Capture output to check for warnings/errors
    LOG_FILE=$(mktemp)
    if run_tidy 2>&1 | tee "$LOG_FILE"; then
        if grep -q "warning:" "$LOG_FILE" 2>/dev/null || grep -q "error:" "$LOG_FILE" 2>/dev/null; then
            echo "✗ clang-tidy check failed. Issues found."
            rm -f "$LOG_FILE"
            exit 1
        else
            echo "✓ clang-tidy check passed"
            rm -f "$LOG_FILE"
            exit 0
        fi
    else
        echo "✗ clang-tidy check failed. Fix the issues reported above."
        rm -f "$LOG_FILE"
        exit 1
    fi
else
    # Just run and show output
    if run_tidy; then
        echo "✓ clang-tidy completed"
        exit 0
    else
        echo "✗ clang-tidy found issues. See output above."
        exit 1
    fi
fi
