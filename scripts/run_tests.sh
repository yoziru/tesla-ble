#!/bin/bash

# Tesla BLE Test Runner Script
# This script builds and runs all tests for the Tesla BLE library

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

# Default values
BUILD_TYPE="Debug"
BUILD_DIR="build"
CLEAN_BUILD=false
RUN_COVERAGE=false
RUN_VALGRIND=false
VERBOSE=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -r|--release)
            BUILD_TYPE="Release"
            shift
            ;;
        -c|--clean)
            CLEAN_BUILD=true
            shift
            ;;
        --coverage)
            RUN_COVERAGE=true
            shift
            ;;
        --valgrind)
            RUN_VALGRIND=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  -r, --release     Build in Release mode (default: Debug)"
            echo "  -c, --clean       Clean build directory before building"
            echo "  --coverage        Run with coverage analysis"
            echo "  --valgrind        Run tests with Valgrind"
            echo "  -v, --verbose     Verbose output"
            echo "  -h, --help        Show this help message"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

print_header "Tesla BLE Test Runner"
echo "Build type: $BUILD_TYPE"
echo "Build directory: $BUILD_DIR"
echo "Project directory: $PROJECT_DIR"

# Clean build directory if requested
if [ "$CLEAN_BUILD" = true ]; then
    print_header "Cleaning build directory"
    rm -rf "$BUILD_DIR"
    print_success "Build directory cleaned"
fi

# Create build directory
mkdir -p "$BUILD_DIR"

print_header "Configuring CMake"

# Configure CMake with appropriate flags
CMAKE_FLAGS=(
    "-DCMAKE_BUILD_TYPE=$BUILD_TYPE"
    "-S" "$PROJECT_DIR"
    "-B" "$BUILD_DIR"
)

if [ "$RUN_COVERAGE" = true ]; then
    CMAKE_FLAGS+=("-DCMAKE_CXX_FLAGS=--coverage")
    CMAKE_FLAGS+=("-DCMAKE_C_FLAGS=--coverage")
    print_warning "Coverage analysis enabled"
fi

if ! cmake "${CMAKE_FLAGS[@]}"; then
    print_error "CMake configuration failed"
    exit 1
fi

print_success "CMake configuration completed"

print_header "Building project"

if [ "$VERBOSE" = true ]; then
    BUILD_FLAGS=("--verbose")
else
    BUILD_FLAGS=()
fi

if ! cmake --build "$BUILD_DIR" --config "$BUILD_TYPE" "${BUILD_FLAGS[@]}"; then
    print_error "Build failed"
    exit 1
fi

print_success "Build completed successfully"

print_header "Running tests"

cd "$BUILD_DIR"

CTEST_FLAGS=(
    "--build-config" "$BUILD_TYPE"
    "--output-on-failure"
    "-R" "Tesla|Client|Key|Message|Session|Utils"
)

if [ "$VERBOSE" = true ]; then
    CTEST_FLAGS+=("--verbose")
fi

if [ "$RUN_VALGRIND" = true ]; then
    if command -v valgrind &> /dev/null; then
        CTEST_FLAGS+=("-T" "memcheck")
        print_warning "Running tests with Valgrind"
    else
        print_warning "Valgrind not found, running tests normally"
    fi
fi

if ! ctest "${CTEST_FLAGS[@]}"; then
    print_error "Some tests failed"
    exit 1
fi

print_success "All tests passed"

# Generate coverage report if enabled
if [ "$RUN_COVERAGE" = true ]; then
    print_header "Generating coverage report"
    
    if command -v lcov &> /dev/null; then
        lcov --capture --directory . --output-file coverage.info
        lcov --remove coverage.info '/usr/*' --output-file coverage.info
        lcov --remove coverage.info '*/_deps/*' --output-file coverage.info
        lcov --remove coverage.info '*/tests/*' --output-file coverage.info
        
        if command -v genhtml &> /dev/null; then
            genhtml coverage.info --output-directory coverage_html
            print_success "Coverage report generated in coverage_html/"
        else
            print_warning "genhtml not found, coverage report not generated"
        fi
        
        lcov --list coverage.info
    else
        print_warning "lcov not found, coverage report not generated"
    fi
fi

print_header "Test run completed successfully"
print_success "All tests completed successfully!"

# Return to original directory
cd "$PROJECT_DIR"
