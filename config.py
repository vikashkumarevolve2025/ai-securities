"""Lab configuration. Change the profile, region or default model here."""

PROFILE_NAME = "foresight"
REGION = "us-east-1"

# Claude 3.7 Sonnet has reached end-of-life on Bedrock, so the lab defaults to Sonnet 5.5.
DEFAULT_MODEL = "us.anthropic.claude-sonnet-5-5"

# Models offered in the UI. Older/smaller models are useful for comparing how
# susceptible different models are to the same attack.
MODELS = [
    "us.anthropic.claude-sonnet-5-5",
    "us.anthropic.claude-haiku-5-5",
    "us.anthropic.claude-opus-5-5",
    "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
    "us.anthropic.claude-haiku-4-5-20251001-v1:0",
]

# Recommended model for the "Vulnerable" demo: strong models (Sonnet/Opus 5.x) resist most of
# these attacks on their own, which hides the point. Haiku 4.5 lets the vulnerable lane actually
# land, so you can watch the defenses block it in Secure mode.
DEMO_MODEL = "us.anthropic.claude-haiku-4-5-20251001-v1:0"

MAX_TOKENS = 800
MAX_AGENT_STEPS = 6
