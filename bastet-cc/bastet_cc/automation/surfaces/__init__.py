"""HTTP surface adapters for the automation bridge."""

from .n8n import N8NSurface
from .openai import OpenAISurface

__all__ = ["N8NSurface", "OpenAISurface"]
