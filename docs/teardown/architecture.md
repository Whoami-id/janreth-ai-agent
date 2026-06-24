# Janreth — architecture description (GCC Platform intake)

This is the prose system description to paste into the Janreth GCC Platform
(`POST /generate`) to produce an agentic-AI threat assessment of this framework.
Run it twice — once as "controls off" (the raw surface) and once as "controls on"
(the residual surface after the secure-by-default control set).

---

## System: Janreth — a Python AI-agent framework

Janreth is an autonomous AI-agent framework. An agent runs a ReAct loop: it sends
the conversation and a set of tool definitions to a large language model (via
LiteLLM, so any provider — OpenAI, Anthropic — can back it), the model decides
whether to answer or call a tool, the framework executes the requested tools, and
the loop repeats until the model returns a final answer or a step limit is hit.

**Tools.** The agent can call: a web search tool (Tavily) that returns external
web content; a Python code-execution tool and a bash tool that run code in an E2B
cloud sandbox; a file/upload tool that reads local files and writes into the
sandbox; document/media readers (PDF, spreadsheets, images, audio); and tools
discovered from external Model Context Protocol (MCP) servers over stdio. Tool
arguments come from the model.

**Memory and knowledge.** A session store holds the running conversation.
Long-term memory persists structured records of past tasks in a ChromaDB vector
store, embedded with an external embeddings API; relevant past records are
retrieved by similarity and injected into the prompt automatically. A retrieval
(RAG) component chunks and embeds documents for vector search.

**Multi-agent.** Agents can hand off control to other agents (the receiving agent
inherits the full conversation), call another agent as a tool, and call remote
agents over HTTP using an agent-to-agent (A2A) JSON-RPC protocol, discovering a
peer via its published agent card. Workflow primitives chain agents sequentially,
run them in parallel, or loop until a condition holds.

**Data flows.** Untrusted external content enters through web search results, file
and document contents, MCP tool outputs, and A2A peer replies, and is fed back
into the model's prompt. Tool outputs and the model's outputs are recorded as the
conversation history. Secrets (provider API keys) are read from the environment.

## Controls-on variant (append this for the second pass)

The same system, with Janreth's security layer enabled by default: a default-deny
tool policy with path-traversal and call-budget constraints; human confirmation
required before high-impact tools (code execution, file writes, sending);
secret/PII redaction of tool outputs and prompts; rule-based prompt-injection
screening of user input and tool output; sanitization of active content;
neutralization and enveloping of recalled long-term memory; static network-egress
denial for sandboxed code; narrowing-only delegation scopes and signed A2A
messages; tool-provenance recording with a trusted-MCP allow-list; and a
tamper-evident, hash-chained audit trail of every security decision.
