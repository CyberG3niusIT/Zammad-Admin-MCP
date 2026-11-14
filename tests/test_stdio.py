"""Real stdio process discovery; no Zammad endpoint is contacted."""
import asyncio
import json
from pathlib import Path
import sys
import unittest

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


class StdioTests(unittest.IsolatedAsyncioTestCase):
    async def test_initialization_discovery_and_invalid_plan(self):
        params = StdioServerParameters(command=sys.executable, args=["-m", "zammad_admin_mcp.server"], env={})
        async with asyncio.timeout(30):
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    initialized = await session.initialize()
                    self.assertEqual(initialized.serverInfo.name, "zammad-admin")
                    discovery = await session.list_tools()
                    names = [tool.name for tool in discovery.tools]
                    self.assertEqual(len(names), len(set(names)))
                    for required in ("zammad_server_version", "zammad_list_admin_resources", "zammad_list_admin_resource", "zammad_get_admin_object", "zammad_apply_admin_change"):
                        self.assertIn(required, names)
                    for tool in discovery.tools:
                        self.assertEqual(tool.inputSchema.get("type"), "object")
                    inventory = {"transport": "actual stdio subprocess", "server": initialized.serverInfo.model_dump(mode="json"), "count": len(names), "tools": [tool.model_dump(mode="json") for tool in discovery.tools]}
                    Path(__file__).with_name("stdio_tool_inventory.json").write_text(json.dumps(inventory, indent=2), encoding="utf-8")
                    rows = ["# Actual MCP tool test matrix", "", "Registry and object-schema checks below were performed through a real local stdio subprocess. No ContextForge or Zammad API endpoint was contacted. Schema checks establish top-level object shape, not exhaustive input-domain validation. All administrative live writes remain unverified.", "", "| Tool | stdio discovery | Object schema | Functional evidence | Live API / ContextForge |", "|---|---|---|---|---|"]
                    for name in names:
                        evidence = "Not individually exercised"
                        if name == "zammad_list_admin_resources":
                            evidence = "Real stdio call succeeds (local resource catalog)"
                        elif name == "zammad_apply_admin_change":
                            evidence = "Real stdio invalid-plan rejection; synthetic expired/replay/stale/high-impact/queued-expiration and successful PUT tests"
                        rows.append(f"| `{name}` | PASS | PASS | {evidence} | NOT VERIFIED |")
                    Path(__file__).with_name("TOOL_TEST_MATRIX.md").write_text("\n".join(rows) + "\n", encoding="utf-8")
                    rejected = await session.call_tool("zammad_apply_admin_change", {"plan_id": "synthetic-nonexistent-plan"})
                    self.assertTrue(rejected.isError)
                    resources = await session.call_tool("zammad_list_admin_resources", {})
                    self.assertFalse(resources.isError)


if __name__ == "__main__":
    unittest.main()
