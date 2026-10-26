from lab.modules import (
    authorization,
    data_leak,
    indirect_injection,
    mcp_tools,
    memory_poisoning,
    prompt_injection,
    rag_poisoning,
)

MODULES = [
    prompt_injection,
    indirect_injection,
    rag_poisoning,
    memory_poisoning,
    mcp_tools,
    authorization,
    data_leak,
]
