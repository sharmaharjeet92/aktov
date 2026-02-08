"""Python DSL for writing Aktov detection rules.

Rules are Python functions decorated with ``@Rule(...)`` that receive a
trace and return a boolean (or a reason string) indicating whether the
rule matched.

Example::

    @Rule(id="AK-001", name="SQL after file read", severity="high", category="exfil")
    def sql_after_file_read(trace):
        return (
            action_chain(trace)
            .sequence(
                first=lambda a: a.tool_category == "read",
                then=lambda a: a.semantic_flags.sql_statement_type is not None,
                max_gap=3,
            )
        )
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from aktov.schema import Action, TracePayload

# ---------------------------------------------------------------------------
# ActionChain — fluent query API over a list of actions
# ---------------------------------------------------------------------------

class ActionChain:
    """Fluent query interface over a trace's action list.

    Provides ``any``, ``all``, ``sequence``, and ``count`` methods for
    pattern matching against ordered tool invocations.
    """

    def __init__(self, actions: list[Action]) -> None:
        self._actions = actions

    def any(self, predicate: Callable[[Action], bool]) -> bool:
        """Return True if *any* action matches the predicate."""
        return any(predicate(a) for a in self._actions)

    def all(self, predicate: Callable[[Action], bool]) -> bool:
        """Return True if *all* actions match the predicate."""
        if not self._actions:
            return False
        return all(predicate(a) for a in self._actions)

    def count(self, predicate: Callable[[Action], bool]) -> int:
        """Return the number of actions matching the predicate."""
        return sum(1 for a in self._actions if predicate(a))

    def sequence(
        self,
        first: Callable[[Action], bool],
        then: Callable[[Action], bool],
        *,
        max_gap: int | None = None,
    ) -> bool:
        """Return True if ``first`` is followed by ``then`` within ``max_gap`` steps.

        If ``max_gap`` is None, any distance is allowed.  A gap of 1
        means the ``then`` action must be the very next action after
        ``first``.
        """
        for i, action_a in enumerate(self._actions):
            if not first(action_a):
                continue

            # Scan forward from action_a
            search_end = len(self._actions)
            if max_gap is not None:
                search_end = min(i + 1 + max_gap, len(self._actions))

            for j in range(i + 1, search_end):
                if then(self._actions[j]):
                    return True

        return False

    def window(
        self,
        predicate: Callable[[Action], bool],
        size: int,
        *,
        min_matches: int = 1,
    ) -> bool:
        """Return True if any sliding window of ``size`` contains at least
        ``min_matches`` actions matching the predicate.
        """
        if size <= 0 or len(self._actions) < size:
            return False

        for start in range(len(self._actions) - size + 1):
            window_slice = self._actions[start : start + size]
            matches = sum(1 for a in window_slice if predicate(a))
            if matches >= min_matches:
                return True

        return False


def action_chain(trace: TracePayload) -> ActionChain:
    """Create an :class:`ActionChain` from a trace payload."""
    return ActionChain(trace.actions)


# ---------------------------------------------------------------------------
# Rule decorator
# ---------------------------------------------------------------------------

# Global registry of all decorated rules
_RULE_REGISTRY: list[Rule] = []


@dataclass
class Rule:
    """Decorator that marks a function as a Aktov detection rule.

    Usage::

        @Rule(id="AK-001", name="Suspicious pattern", severity="high", category="exfil")
        def my_rule(trace: TracePayload) -> bool:
            ...
    """

    id: str
    name: str
    severity: str = "medium"
    category: str = "general"

    # Populated by __call__ when used as a decorator
    _fn: Callable[..., Any] | None = field(default=None, repr=False)

    def __call__(self, fn: Callable[..., Any]) -> Rule:
        """When used as a decorator, capture the rule function."""
        self._fn = fn
        _RULE_REGISTRY.append(self)
        return self

    def evaluate(self, trace: TracePayload) -> bool | str:
        """Evaluate this rule against a trace.

        Returns True/str if the rule matched, False otherwise.
        """
        if self._fn is None:
            raise RuntimeError(f"Rule {self.id} has no evaluation function")
        result = self._fn(trace)
        return result


def get_registered_rules() -> list[Rule]:
    """Return all rules registered via the ``@Rule`` decorator."""
    return list(_RULE_REGISTRY)


def clear_registry() -> None:
    """Clear the global rule registry (useful for testing)."""
    _RULE_REGISTRY.clear()
