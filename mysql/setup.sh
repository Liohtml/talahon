#!/usr/bin/env bash
# Talon MySQL MCP — one-time setup
#
# Creates .env from .env.example if it is not present yet. The MySQL MCP
# server itself is pre-installed in the agent image (/opt/mysql-mcp), so the
# host needs nothing else.
#
# After running this, edit .env with your MySQL credentials.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"

echo "=== Talon MySQL MCP Setup ==="
echo ""

# ── .env ─────────────────────────────────────────────────────────────────────
if [[ ! -f "$ENV_FILE" ]]; then
    cp "$SCRIPT_DIR/.env.example" "$ENV_FILE"
    echo ""
    echo "  Created .env from template."
    echo "  ➜ Edit $ENV_FILE with your MySQL credentials before starting Talon."
    echo ""
else
    echo ".env exists  ✓"
fi

chmod +x "$SCRIPT_DIR/mysql-mcp.sh"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "=== Setup complete! ==="
echo ""
if grep -q "your-username" "$ENV_FILE" 2>/dev/null; then
    echo "Next steps:"
    echo "  1. Edit mysql/.env with your MySQL host, user, password, and database"
    echo "  2. Restart Talon"
else
    echo "Restart Talon to pick up the MySQL MCP server."
fi
echo ""
