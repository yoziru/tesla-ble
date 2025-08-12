#!/bin/bash

# Tesla BLE Development Environment Setup Script
# This script sets up the development environment for the Tesla BLE library

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

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

# Detect OS
OS=""
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
    OS="windows"
else
    print_error "Unsupported operating system: $OSTYPE"
    exit 1
fi

print_header "Tesla BLE Development Environment Setup"
print_info "Detected OS: $OS"

# Check for required tools
print_header "Checking for required tools"

check_command() {
    if command -v "$1" &> /dev/null; then
        print_success "$1 is installed"
        return 0
    else
        print_warning "$1 is not installed"
        return 1
    fi
}

# Essential tools
MISSING_TOOLS=()

if ! check_command cmake; then
    MISSING_TOOLS+=("cmake")
fi

if ! check_command git; then
    MISSING_TOOLS+=("git")
fi

# Compiler checks
if [[ "$OS" == "linux" ]]; then
    if ! check_command gcc && ! check_command clang; then
        MISSING_TOOLS+=("gcc or clang")
    fi
elif [[ "$OS" == "macos" ]]; then
    if ! check_command clang; then
        MISSING_TOOLS+=("clang (Xcode command line tools)")
    fi
fi

# Optional but recommended tools
OPTIONAL_MISSING=()

if ! check_command protoc; then
    OPTIONAL_MISSING+=("protobuf-compiler")
fi

if ! check_command lcov; then
    OPTIONAL_MISSING+=("lcov (for coverage)")
fi

if ! check_command valgrind && [[ "$OS" != "macos" ]]; then
    OPTIONAL_MISSING+=("valgrind (for memory checking)")
fi

if ! check_command cppcheck; then
    OPTIONAL_MISSING+=("cppcheck (for static analysis)")
fi

# Install missing tools
if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
    print_header "Installing missing essential tools"
    
    if [[ "$OS" == "linux" ]]; then
        print_info "Installing on Linux (assuming Ubuntu/Debian)"
        sudo apt-get update
        for tool in "${MISSING_TOOLS[@]}"; do
            case $tool in
                cmake)
                    sudo apt-get install -y cmake
                    ;;
                git)
                    sudo apt-get install -y git
                    ;;
                "gcc or clang")
                    sudo apt-get install -y build-essential
                    ;;
            esac
        done
    elif [[ "$OS" == "macos" ]]; then
        print_info "Installing on macOS"
        if ! command -v brew &> /dev/null; then
            print_info "Installing Homebrew first..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        fi
        
        for tool in "${MISSING_TOOLS[@]}"; do
            case $tool in
                cmake)
                    brew install cmake
                    ;;
                git)
                    brew install git
                    ;;
                "clang (Xcode command line tools)")
                    xcode-select --install || true
                    ;;
            esac
        done
    elif [[ "$OS" == "windows" ]]; then
        print_warning "Please install the following tools manually on Windows:"
        for tool in "${MISSING_TOOLS[@]}"; do
            echo "  - $tool"
        done
        print_info "Consider using vcpkg or chocolatey for easier package management"
    fi
else
    print_success "All essential tools are installed"
fi

# Install optional tools
if [ ${#OPTIONAL_MISSING[@]} -gt 0 ]; then
    print_header "Installing optional development tools"
    
    if [[ "$OS" == "linux" ]]; then
        for tool in "${OPTIONAL_MISSING[@]}"; do
            case $tool in
                "protobuf-compiler")
                    sudo apt-get install -y protobuf-compiler
                    ;;
                "lcov (for coverage)")
                    sudo apt-get install -y lcov
                    ;;
                "valgrind (for memory checking)")
                    sudo apt-get install -y valgrind
                    ;;
                "cppcheck (for static analysis)")
                    sudo apt-get install -y cppcheck
                    ;;
            esac
        done
    elif [[ "$OS" == "macos" ]]; then
        for tool in "${OPTIONAL_MISSING[@]}"; do
            case $tool in
                "protobuf-compiler")
                    brew install protobuf
                    ;;
                "lcov (for coverage)")
                    brew install lcov
                    ;;
                "cppcheck (for static analysis)")
                    brew install cppcheck
                    ;;
            esac
        done
    fi
fi

# Setup git hooks (if in a git repository)
if [ -d ".git" ]; then
    print_header "Setting up git hooks"
    
    # Create pre-commit hook
    cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
# Pre-commit hook for Tesla BLE

echo "Running pre-commit checks..."

# Run static analysis
if command -v cppcheck &> /dev/null; then
    echo "Running cppcheck..."
    cppcheck --enable=warning,style,performance,portability --error-exitcode=1 \
        --suppress=missingIncludeSystem \
        src/ include/ examples/ || exit 1
fi

# Run tests
echo "Running tests..."
if [ -f "scripts/run_tests.sh" ]; then
    ./scripts/run_tests.sh --release || exit 1
fi

echo "Pre-commit checks passed!"
EOF
    
    chmod +x .git/hooks/pre-commit
    print_success "Git pre-commit hook installed"
else
    print_warning "Not in a git repository, skipping git hooks setup"
fi

print_header "Development Environment Setup Complete"
print_success "Your development environment is now ready!"

print_info "Next steps:"
echo "  1. Build the project: cmake -B build && cmake --build build"
echo "  2. Run tests: ./scripts/run_tests.sh"
echo "  3. Run tests with coverage: ./scripts/run_tests.sh --coverage"
echo "  4. For help with the test runner: ./scripts/run_tests.sh --help"

if [ ${#OPTIONAL_MISSING[@]} -gt 0 ]; then
    print_info "Some optional tools are still missing:"
    for tool in "${OPTIONAL_MISSING[@]}"; do
        echo "  - $tool"
    done
    print_info "These are not required but recommended for development"
fi
