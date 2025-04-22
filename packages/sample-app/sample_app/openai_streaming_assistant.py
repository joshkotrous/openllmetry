from typing_extensions import override
from openai import OpenAI, AssistantEventHandler
from traceloop.sdk import Traceloop
import re

Traceloop.init()

client = OpenAI()


def is_malicious_prompt(prompt: str) -> bool:
    # Disallow prompts with code, system, or security-critical language.
    forbidden_keywords = [
        "import", "os.", "sys.", "open(", "exec", "eval", "subprocess", "system(", "file",
        "write", "read", "remove", "delete", "copy", "move", "pip", "install", "socket", "net",
        "bash", "sh", "root", "admin", "token", "key", "secret", "password", "env", "environment",
        "upload", "download", "network", "fork", "thread", "process", "memory", "cpu", "kill", "shutdown"
    ]
    pattern = re.compile(r"|".join([re.escape(kw) for kw in forbidden_keywords]), re.IGNORECASE)
    return pattern.search(prompt) is not None


def sanitize_output(text: str) -> str:
    # Redact common sensitive patterns (paths, Traceback, env, etc)
    sensitive_patterns = [
        r"Traceback \(most recent call last\):",      # Python exception
        r"File \".*?\"",                             # File paths
        r"os\.environ.*",                            # Env info
        r"(?i)password\s*=\s*['\"].*?['\"]",         # Password assignment
        r"['\"]sk-[a-zA-Z0-9]{20,}['\"]",            # Possible OpenAI style keys
        r"[/\\][\w.-]+[/\\][\w.\-\\]+",              # Generic file path
        r"\b(token|api[_-]?key|secret)\b.{0,40}",    # Key leakage
        r"Process[^\n]*\n",                          # Process info
        r"Permission denied",                        # Permissions
        r"Operation not permitted",
    ]
    redacted = text
    for pat in sensitive_patterns:
        redacted = re.sub(pat, "[REDACTED]", redacted)
    return redacted

assistant = client.beta.assistants.create(
    name="Math Tutor",
    instructions="You are a personal math tutor. Write and run code to answer math questions.",
    tools=[{"type": "code_interpreter"}],
    model="gpt-4-turbo-preview",
)

# User input for math solution
user_prompt = "I need to solve the equation `3x + 11 = 14`. Can you help me?"

# Input validation: allow only basic arithmetic/math wording
if is_malicious_prompt(user_prompt):
    raise ValueError(
        "Prompt rejected: Please submit only basic math equations. "
        "No code, system, or file operations are allowed."
    )

thread = client.beta.threads.create()

message = client.beta.threads.messages.create(
    thread_id=thread.id,
    role="user",
    content=user_prompt,
)

# Event handler with output sanitization
class EventHandler(AssistantEventHandler):
    @override
    def on_text_created(self, text) -> None:
        print("\nassistant > ", end="", flush=True)

    @override
    def on_text_delta(self, delta, snapshot):
        print(delta.value, end="", flush=True)

    def on_tool_call_created(self, tool_call):
        print(f"\nassistant > {tool_call.type}\n", flush=True)

    def on_tool_call_delta(self, delta, snapshot):
        if delta.type == "code_interpreter":
            if delta.code_interpreter.input:
                # Sanitize input shown from LLM
                safe_input = sanitize_output(delta.code_interpreter.input)
                print(safe_input, end="", flush=True)
            if delta.code_interpreter.outputs:
                print("\n\noutput >", flush=True)
                for output in delta.code_interpreter.outputs:
                    if output.type == "logs":
                        safe_log = sanitize_output(output.logs)
                        print(f"\n{safe_log}", flush=True)

with client.beta.threads.runs.create_and_stream(
    thread_id=thread.id,
    assistant_id=assistant.id,
    instructions="Please address the user as Jane Doe. The user has a premium account.",
    event_handler=EventHandler(),
) as stream:
    stream.until_done()