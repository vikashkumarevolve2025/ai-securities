"""Thin wrapper around the Bedrock Converse API, plus a simple tool-calling agent loop."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

import boto3
from botocore.exceptions import ClientError

import config

_client = None


def client():
    global _client
    if _client is None:
        session = boto3.Session(profile_name=config.PROFILE_NAME, region_name=config.REGION)
        _client = session.client("bedrock-runtime")
    return _client


def _converse(**kwargs):
    # Newer Claude models reject `temperature`; retry without it if needed.
    try:
        return client().converse(**kwargs)
    except ClientError as e:
        if "temperature" in str(e) and "temperature" in kwargs.get("inferenceConfig", {}):
            kwargs["inferenceConfig"] = {k: v for k, v in kwargs["inferenceConfig"].items() if k != "temperature"}
            return client().converse(**kwargs)
        raise


def chat(system: str, user: str, model: str | None = None) -> str:
    """Single-turn call. Returns the model's text."""
    resp = _converse(
        modelId=model or config.DEFAULT_MODEL,
        system=[{"text": system}] if system else [],
        messages=[{"role": "user", "content": [{"text": user}]}],
        inferenceConfig={"maxTokens": config.MAX_TOKENS, "temperature": 0},
    )
    return "".join(b.get("text", "") for b in resp["output"]["message"]["content"])


@dataclass
class Tool:
    name: str
    description: str
    params: dict  # JSON schema "properties"
    fn: Callable[..., str]
    required: list[str] = field(default_factory=list)

    def spec(self) -> dict:
        return {
            "toolSpec": {
                "name": self.name,
                "description": self.description,
                "inputSchema": {"json": {"type": "object", "properties": self.params, "required": self.required}},
            }
        }


@dataclass
class AgentResult:
    text: str
    tool_calls: list[dict]  # {"name", "input", "output", "blocked"}


def run_agent(
    system: str,
    user: str,
    tools: list[Tool],
    model: str | None = None,
    guard: Callable[[str, dict], str | None] | None = None,
) -> AgentResult:
    """Run a tool-calling loop. `guard(name, input)` may return a reason string to block a call."""
    by_name = {t.name: t for t in tools}
    messages = [{"role": "user", "content": [{"text": user}]}]
    calls: list[dict] = []
    text = ""
    for _ in range(config.MAX_AGENT_STEPS):
        resp = _converse(
            modelId=model or config.DEFAULT_MODEL,
            system=[{"text": system}],
            messages=messages,
            inferenceConfig={"maxTokens": config.MAX_TOKENS, "temperature": 0},
            toolConfig={"tools": [t.spec() for t in tools]},
        )
        msg = resp["output"]["message"]
        messages.append(msg)
        text = "".join(b.get("text", "") for b in msg["content"])
        if resp["stopReason"] != "tool_use":
            break
        results = []
        for block in msg["content"]:
            if "toolUse" not in block:
                continue
            use = block["toolUse"]
            name, args = use["name"], use.get("input", {})
            reason = guard(name, args) if guard else None
            if reason:
                output = f"BLOCKED by policy: {reason}"
            elif name in by_name:
                output = by_name[name].fn(**args)
            else:
                output = f"Unknown tool {name}"
            calls.append({"name": name, "input": args, "output": output, "blocked": bool(reason)})
            results.append({"toolResult": {"toolUseId": use["toolUseId"], "content": [{"text": output}]}})
        messages.append({"role": "user", "content": results})
    return AgentResult(text=text, tool_calls=calls)
