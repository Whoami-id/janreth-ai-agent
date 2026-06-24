# Build an AI Agent from Scratch


## Structure

```
agents/        
  types.py              # Message, ToolCall, ToolResult, Event, ContentItem
  context.py            # ExecutionContext, AgentResult, PendingToolCall, ToolConfirmation
  llm.py                # LlmRequest, LlmResponse, LlmClient
  agent.py              # Agent (ReAct loop)
  rag.py                # Embeddings, chunking, vector search
  callbacks.py          # approval_callback, search_compressor
  planning.py           # Task, create_tasks, reflection
  skills.py             # SkillInfo, discover_skills, generate_skills_prompt
  transfer.py           # create_transfer_tool
  remote.py             # RemoteAgent (A2A)
  a2a_server.py         # MathAgentExecutor
  tools/                # Tool modules
  memory/               # Session, long-term memory, context optimization
  workflows/            # Sequential, Parallel, Loop
  eval/                 # GAIA benchmark, evaluation prompts


## Setup

```bash
# Install uv (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install dependencies
uv sync

# Set up API keys in .env
cp .env.example .env
# Edit .env and add your API keys
