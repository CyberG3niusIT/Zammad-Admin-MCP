"""Real stdio process discovery; no Zammad endpoint is contacted."""
import asyncio
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
                    rejected = await session.call_tool("zammad_apply_admin_change", {"plan_id": "synthetic-nonexistent-plan"})
                    self.assertTrue(rejected.isError)
                    resources = await session.call_tool("zammad_list_admin_resources", {})
                    self.assertFalse(resources.isError)


if __name__ == "__main__":
    unittest.main()
