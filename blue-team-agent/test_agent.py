import os
import asyncio

os.environ.setdefault('SPANNER_PROJECT_ID', 'zhiting-personal')
os.environ.setdefault('SPANNER_INSTANCE_ID', 'grocerguard-instance')
os.environ.setdefault('SPANNER_DATABASE_ID', 'grocerguard')
# Point the agent at the actual local codebase so list_files/search_code work
os.environ.setdefault('CODEBASE_DIR', '/Users/zhiting/Projects/GrocerGuard-Arena')


from agent import blue_team_agent
from google.adk import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types


async def main():
    print("Initializing Runner...")
    session_service = InMemorySessionService()
    runner = Runner(
        app_name="local_test_app",
        agent=blue_team_agent,
        session_service=session_service
    )

    print("Creating Session...")
    session = await session_service.create_session(app_name="local_test_app", user_id="test_user")

    print("Runner initialized successfully! Testing a simple prompt...")
    final_response = ""
    async for event in runner.run_async(
        user_id="test_user",
        session_id=session.id,
        new_message=types.Content(role="user", parts=[types.Part.from_text(text="Please find the recently injected vulnerability, fix it, verify the fix, and log your defense.")])
    ):
        # Extract text from event parts and print progress
        if event.content and event.content.parts:
            for part in event.content.parts:
                if hasattr(part, 'function_call') and part.function_call:
                    print(f"  [TOOL CALL] {part.function_call.name}({dict(part.function_call.args)})")
                elif hasattr(part, 'function_response') and part.function_response:
                    resp_str = str(part.function_response.response)[:200]
                    print(f"  [TOOL RESULT] {part.function_response.name}: {resp_str}...")
                elif hasattr(part, 'text') and part.text:
                    final_response += part.text

    print("Response:\n", final_response)


if __name__ == "__main__":
    asyncio.run(main())
