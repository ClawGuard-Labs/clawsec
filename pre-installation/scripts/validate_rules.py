#!/usr/bin/env python3
"""
Validate all pre-installation rule YAML files against the rule schema.
Exits with 0 if all rules are valid and exactly 39 unique rule_ids are present.
Usage: python validate_rules.py [--rules-dir DIR] [--schema PATH]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Optional: use jsonschema if available for strict validation
try:
    import jsonschema
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False

try:
    import yaml
except ImportError:
    print("Error: PyYAML is required. Install with: pip install pyyaml", file=sys.stderr)
    sys.exit(2)

# Expected total number of rules (from full rule inventory)
EXPECTED_RULE_COUNT = 43

# Script is in pre-installation/scripts/; repo root is two levels up from script dir
SCRIPT_DIR = Path(__file__).resolve().parent
PREINSTALL_DIR = SCRIPT_DIR.parent
DEFAULT_RULES_DIR = PREINSTALL_DIR / "rules"
DEFAULT_SCHEMA_PATH = PREINSTALL_DIR / "schema" / "rule_schema.json"


def load_schema(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_rule(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if data is None:
        raise ValueError(f"Empty YAML: {path}")
    return data


def validate_rule_required_fields(rule: dict, path: Path) -> list[str]:
    errors = []
    required = ["rule_id", "name", "description", "severity", "action", "category"]
    for field in required:
        if field not in rule or rule[field] is None or rule[field] == "":
            errors.append(f"{path}: missing or empty required field '{field}'")
    if "severity" in rule and rule["severity"] not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        errors.append(f"{path}: invalid severity '{rule['severity']}'")
    if "action" in rule and rule["action"] not in ("BLOCK", "WARN", "AUDIT"):
        errors.append(f"{path}: invalid action '{rule['action']}'")
    if "rule_id" in rule and isinstance(rule["rule_id"], str):
        import re
        if not re.match(r"^AI-[A-Z]{2}-[0-9]{3}$", rule["rule_id"]):
            errors.append(f"{path}: rule_id must match pattern AI-XX-NNN, got '{rule['rule_id']}'")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate pre-installation AI security rules")
    parser.add_argument("--rules-dir", type=Path, default=DEFAULT_RULES_DIR, help="Directory containing rules/ subdirs")
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA_PATH, help="Path to rule_schema.json")
    parser.add_argument("--no-jsonschema", action="store_true", help="Skip jsonschema validation (only check required fields and count)")
    args = parser.parse_args()

    rules_dir = args.rules_dir
    schema_path = args.schema

    if not rules_dir.is_dir():
        print(f"Error: rules directory not found: {rules_dir}", file=sys.stderr)
        return 2
    if not schema_path.is_file():
        print(f"Error: schema file not found: {schema_path}", file=sys.stderr)
        return 2

    schema = load_schema(schema_path) if HAS_JSONSCHEMA and not args.no_jsonschema else None
    all_errors: list[str] = []
    rule_ids: set[str] = set()
    rule_files = sorted(rules_dir.rglob("*.yaml"))

    for path in rule_files:
        try:
            rule = load_rule(path)
        except Exception as e:
            all_errors.append(f"{path}: failed to load YAML: {e}")
            continue

        all_errors.extend(validate_rule_required_fields(rule, path))

        if schema and HAS_JSONSCHEMA:
            try:
                jsonschema.validate(instance=rule, schema=schema)
            except jsonschema.ValidationError as e:
                all_errors.append(f"{path}: schema validation failed: {e.message}")

        rid = rule.get("rule_id")
        if rid:
            if rid in rule_ids:
                all_errors.append(f"{path}: duplicate rule_id '{rid}'")
            rule_ids.add(rid)

    if all_errors:
        for err in all_errors:
            print(err, file=sys.stderr)
        print(f"\nTotal errors: {len(all_errors)}", file=sys.stderr)
        return 1

    if len(rule_ids) != EXPECTED_RULE_COUNT:
        print(f"Error: expected {EXPECTED_RULE_COUNT} unique rule_ids, found {len(rule_ids)}", file=sys.stderr)
        missing = set(f"AI-{c}-{n:03d}" for c in ["CE", "SC", "MF", "LC", "DP", "PD", "ID", "BA", "IR", "RC"] for n in range(1, 10))  # approximate
        # Simpler: just report count
        return 1

    print(f"OK: {len(rule_ids)} rules validated successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
