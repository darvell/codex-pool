#!/usr/bin/env python3
"""Validate one real Operator API response against the bundled OpenAPI schema.

Usage: validate_operator_api_payload.py SPEC METHOD PATH < payload.json
Requires the development-only `jsonschema` Python package.
"""

import copy
import json
import pathlib
import sys

from jsonschema import Draft202012Validator


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit("usage: validate_operator_api_payload.py SPEC METHOD PATH")
    spec = json.loads(pathlib.Path(sys.argv[1]).read_text())
    method, path = sys.argv[2].lower(), sys.argv[3]
    response_schema = spec["paths"][path][method]["responses"]["200"]["content"]["application/json"]["schema"]
    schema = copy.deepcopy(response_schema)
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["components"] = spec["components"]
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(json.load(sys.stdin))


if __name__ == "__main__":
    main()
