"""CLI handlers for ``aktov rules`` subcommands.

Commands::

    aktov rules schema [--fields|--operators|--match-types]
    aktov rules validate <file>
    aktov rules examples
"""

from __future__ import annotations

import argparse
import sys

import yaml

from aktov.rules.validator import (
    format_examples_output,
    format_schema_output,
    format_validation_results,
    validate_rule,
)


def cmd_rules_schema(args: argparse.Namespace) -> None:
    """Print available fields, operators, and match types."""
    section = None
    if getattr(args, "fields", False):
        section = "fields"
    elif getattr(args, "operators", False):
        section = "operators"
    elif getattr(args, "match_types", False):
        section = "match-types"

    print(format_schema_output(section))


def cmd_rules_validate(args: argparse.Namespace) -> None:
    """Validate a rule YAML file."""
    filepath = args.file

    try:
        with open(filepath, encoding="utf-8") as f:
            docs = list(yaml.safe_load_all(f))
    except FileNotFoundError:
        print(f"\n  ERROR: File not found: {filepath}\n", file=sys.stderr)
        sys.exit(1)
    except yaml.YAMLError as exc:
        print(f"\n  ERROR: Invalid YAML syntax in {filepath}:\n  {exc}\n", file=sys.stderr)
        sys.exit(1)

    all_errors = []
    for doc in docs:
        if doc is None:
            continue
        all_errors.extend(validate_rule(doc))

    print(format_validation_results(all_errors, filepath))

    has_errors = any(e.severity == "error" for e in all_errors)
    if has_errors:
        sys.exit(1)


def cmd_rules_examples(args: argparse.Namespace) -> None:
    """Print rule-writing guide with examples."""
    print(format_examples_output())
