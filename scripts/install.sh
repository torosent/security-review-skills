#!/bin/bash
# Install security-review skill globally for Copilot CLI
set -e

SKILL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TARGET_DIR="$HOME/.copilot/skills/security-review"

# Create skills directory if it doesn't exist
mkdir -p "$HOME/.copilot/skills"

# Remove existing symlink or directory
if [ -L "$TARGET_DIR" ]; then
    echo "Removing existing symlink..."
    rm "$TARGET_DIR"
elif [ -d "$TARGET_DIR" ]; then
    echo "Warning: $TARGET_DIR exists as a directory. Backing up..."
    mv "$TARGET_DIR" "${TARGET_DIR}.bak.$(date +%s)"
fi

# Create symlink
ln -s "$SKILL_DIR" "$TARGET_DIR"
echo "✅ Installed security-review skill"
echo "   Source: $SKILL_DIR"
echo "   Target: $TARGET_DIR"
echo ""
echo "The skill is now available in Copilot CLI."
