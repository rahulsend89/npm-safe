#!/bin/bash

# Node Firewall Installation Script
# Robust installation with detection, update, and uninstall options

set -e

FIREWALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$FIREWALL_DIR/bin"
MARKER_START="# Node Firewall - START"
MARKER_END="# Node Firewall - END"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_header() {
  echo "==================================================="
  echo "   $1"
  echo "==================================================="
  echo ""
}

print_ok() {
  echo -e "${GREEN}[OK]${NC} $1"
}

print_skip() {
  echo -e "${YELLOW}[SKIP]${NC} $1"
}

print_error() {
  echo -e "${RED}[ERROR]${NC} $1"
}

# Check if firewall is installed in a shell profile
is_installed() {
  local file="$1"
  if [ -f "$file" ]; then
    grep -q "$MARKER_START" "$file" 2>/dev/null
    return $?
  fi
  return 1
}

# Remove existing installation from a file
remove_from_file() {
  local file="$1"
  if [ -f "$file" ]; then
    if is_installed "$file"; then
      # Use sed to remove everything between markers (including markers)
      sed -i.bak "/$MARKER_START/,/$MARKER_END/d" "$file"
      rm -f "${file}.bak"
      return 0
    fi
  fi
  return 1
}

# Add firewall to a shell profile
add_to_file() {
  local file="$1"
  local filename=$(basename "$file")
  
  if [ ! -f "$file" ]; then
    print_skip "$filename does not exist"
    return
  fi
  
  echo "Processing $filename..."
  
  # Check if already installed
  if is_installed "$file"; then
    # Check if path is different (update needed)
    if grep -q "$BIN_DIR" "$file"; then
      print_skip "Already installed in $filename with correct path"
    else
      print_error "Installed but path is outdated in $filename"
      echo "  Updating installation..."
      remove_from_file "$file"
      add_to_file "$file"
    fi
    return
  fi
  
  # Add installation
  cat >> "$file" << EOF

$MARKER_START
export PATH="$BIN_DIR:\$PATH"
alias npm-safe='$BIN_DIR/npm-safe'
alias firewall-config='$BIN_DIR/firewall-config'
$MARKER_END
EOF
  
  print_ok "Added to $filename"
}

# Uninstall function
uninstall() {
  print_header "Node Firewall Uninstallation"
  
  local removed=0
  
  # Remove from all shell profiles
  for file in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.bash_profile"; do
    if remove_from_file "$file"; then
      print_ok "Removed from $(basename "$file")"
      removed=1
    fi
  done
  
  if [ $removed -eq 0 ]; then
    print_skip "No installation found"
  else
    echo ""
    print_ok "Uninstallation complete!"
    echo ""
    echo "To complete removal:"
    echo "  1. Reload your shell: source ~/.zshrc or source ~/.bashrc"
    echo "  2. Optionally delete this directory"
  fi
  
  exit 0
}

# Install function
install() {
  print_header "Node Firewall Installation"
  
  # Verify required files exist
  if [ ! -f "$BIN_DIR/npm-safe" ]; then
    print_error "npm-safe not found in $BIN_DIR"
    exit 1
  fi
  
  if [ ! -f "$BIN_DIR/firewall-config" ]; then
    print_error "firewall-config not found in $BIN_DIR"
    exit 1
  fi
  
  # Make sure bin files are executable
  chmod +x "$BIN_DIR/npm-safe" "$BIN_DIR/firewall-config" "$BIN_DIR/node-firewall" 2>/dev/null
  
  # Add to shell profiles
  add_to_file "$HOME/.zshrc"
  add_to_file "$HOME/.bashrc"
  add_to_file "$HOME/.bash_profile"
  
  echo ""
  print_header "Installation Complete!"
  
  echo "Next steps:"
  echo "  1. Reload your shell:"
  echo "     ${GREEN}source ~/.zshrc${NC}    (for zsh)"
  echo "     ${GREEN}source ~/.bashrc${NC}   (for bash)"
  echo ""
  echo "  2. Initialize firewall config:"
  echo "     ${GREEN}firewall-config init${NC}"
  echo ""
  echo "  3. Install packages safely:"
  echo "     ${GREEN}npm-safe install${NC}"
  echo ""
  echo "To uninstall: ${GREEN}./install.sh --uninstall${NC}"
  echo ""
}

# Main
case "${1:-}" in
  --uninstall|-u|uninstall)
    uninstall
    ;;
  --help|-h|help)
    echo "Node Firewall Installation Script"
    echo ""
    echo "Usage:"
    echo "  ./install.sh              Install or update"
    echo "  ./install.sh --uninstall  Remove installation"
    echo "  ./install.sh --help       Show this help"
    echo ""
    exit 0
    ;;
  *)
    install
    ;;
esac
