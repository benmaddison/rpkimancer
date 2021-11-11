#!/usr/bin/env python
# Copyright (c) 2021 Ben Maddison. All rights reserved.
#
# The contents of this file are licensed under the MIT License
# (the "License"); you may not use this file except in compliance with the
# License.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.
"""OID registry validator."""

from __future__ import annotations

import json
import logging
import pathlib
import sys

import coloredlogs

import jsonschema

import verboselogs

import yaml

log = verboselogs.VerboseLogger(__name__)

LOG_FMT = "%(levelname)s %(message)s"
LOG_FIELD_STYLES = {"levelname": {"bold": True, "color": "white"}}


def main() -> int:
    """Validate registry data using schema."""
    coloredlogs.install(level=logging.INFO,
                        logger=log,
                        fmt=LOG_FMT,
                        field_styles=LOG_FIELD_STYLES)
    base_path = pathlib.Path(__file__).parent

    schema_path = base_path / "schema.json"
    log.info(f"opening schema '{schema_path}'")
    try:
        with open(schema_path) as f:
            log.info("parsing schema")
            schema = json.load(f)
    except Exception as e:
        log.error(f"failed to read schema: {e}")
        return 2

    data_path = base_path / "registry.yaml"
    log.info(f"opening registry data '{data_path}'")
    try:
        with open(base_path / "registry.yaml") as f:
            log.info("parsing registry data")
            data = yaml.safe_load(f)
    except Exception as e:
        log.error(f"failed to read registry data: {e}")
        return 2

    log.info("trying to get metaschema id")
    metaschema_id = schema.get("$schema")
    if metaschema_id is None:
        log.warning("no '$schema' property found in schema")

    log.info(f"determining validator class for '{metaschema_id}'")
    validator_cls = jsonschema.validators.validator_for(schema, default=None)
    if validator_cls is None:
        log.error("unable to determine validator class")
        return 2

    log.info(f"constructing '{validator_cls.__name__}' validator")
    try:
        validator_cls.check_schema(schema)
        validator = validator_cls(schema)
    except Exception as e:
        log.error(f"failed to construct jsonschema validator: {e}")
        return 2

    log.info("trying to validate registry data")
    errors = sorted(validator.iter_errors(data), key=lambda e: e.path)
    if errors:
        for err in errors:
            log.error(f"validation error:\n{err}")
        return 1

    log.success("no errors found")
    return 0


if __name__ == "__main__":
    rv = main()
    sys.exit(rv)
