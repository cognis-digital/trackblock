"""TRACKBLOCK MCP server — exposes scan as an MCP tool for Cognis.Studio."""
from cognis_core.mcp import build_mcp_server
from trackblock.core import scan, TOOL_NAME

run_mcp_server = build_mcp_server(
    tool_name=TOOL_NAME,
    description="Family phone stalkerware audit — MVT-class iOS/Android forensics",
    scan_fn=scan,
)

if __name__ == "__main__":
    run_mcp_server()
