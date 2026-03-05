"""
Base classes for jailbreak attack demonstrations.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AttackResult:
    """Records the outcome of a single attack attempt."""
    agent: str                     # Which agent was targeted (A1/A2/A3)
    attack_name: str               # Short label for this attack
    vulnerability: str             # What weakness is being exploited
    payload: str                   # The exact adversarial input sent
    response: Optional[str] = None # The agent's response (if run live)
    success: bool = False          # Whether the attack achieved its goal
    notes: str = ""                # Analyst notes / expected behavior

    def summary(self) -> str:
        lines = [
            f"{'='*70}",
            f"Agent       : {self.agent}",
            f"Attack      : {self.attack_name}",
            f"Vulnerability: {self.vulnerability}",
            f"{'-'*70}",
            f"PAYLOAD:\n{self.payload}",
        ]
        if self.response:
            lines += [f"{'-'*70}", f"RESPONSE:\n{self.response}"]
        lines += [
            f"{'-'*70}",
            f"Success: {'YES [PASS]' if self.success else 'NO [not run]'}",
            f"Notes  : {self.notes}",
            f"{'='*70}",
        ]
        return "\n".join(lines)
