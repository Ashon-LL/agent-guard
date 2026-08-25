"""agent-guard core: a reliability layer for autonomous AI agents.

Four pillars (see docs/architecture.md):

  Scope           - where the agent may act          -> policy.py
  Recoverability  - whether mistakes can be undone   -> recovery.py
  Authorization   - who decides what                 -> policy.py (mode state)
  Auditability    - what actually happened           -> audit.py

classifier.py turns shell commands or explicit path lists into structured
operation facts; policy.py turns facts into verdicts; recovery.py executes
compensations (relocate / snapshot); audit.py records everything.

Guiding principle: uncertainty increases restriction (fail closed).
"""

__version__ = "0.1.1"

TRASH_DIRNAME = ".agent-trash"
MANIFEST_NAME = "manifest.jsonl"
AUDIT_NAME = "audit.jsonl"
STATE_NAME = "state.json"
