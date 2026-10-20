"""Agent-agnostic development harness for LionLock OSS.

The harness answers one question: did the job produce the specified end product? Two agents may
write different code; ``make verify SPEC=<ID>`` must report the same fingerprint for both.
"""

__all__ = ["fingerprint", "specs", "verify"]
