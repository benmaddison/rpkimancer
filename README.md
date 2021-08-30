# rpkimancer

![animated rpkimancer](docs/_static/rpkimancer.png)

> **rpkimancer** /ɑː-piː-keɪ-aɪ-mænsə/
>
> *"One who may be called upon to perform those secret rites and incantations
> necessary for the creation or interpretation of the mystical artifacts of the
> RPKI."*

[![CI/CD](https://github.com/benmaddison/rpkimancer/actions/workflows/cicd.yml/badge.svg?event=push)](https://github.com/benmaddison/rpkimancer/actions/workflows/cicd.yml)
[![codecov](https://codecov.io/gh/benmaddison/rpkimancer/branch/main/graph/badge.svg?token=RkTp3eCsOd)](https://codecov.io/gh/benmaddison/rpkimancer)
[![Updates](https://pyup.io/repos/github/benmaddison/rpkimancer/shield.svg)](https://pyup.io/repos/github/benmaddison/rpkimancer/)

## About

A library and associated command line utility for quickly creating and reading
arbitrary RPKI signed objects.

The primary motivation was to be able to construct new RPKI signed object types
directly from an ASN.1 `CONTENT-TYPE` instance definition with minimal
boilerplate and zero custom encoding logic.

The base distribution comes with the necessary plumbing to read and write the
currently standardised object types:

- Manifests (RFC6486)
- ROAs (RFC6482)
- Ghostbuster Records (RFC6493)

Additional signed objects can be supported via a plug-in system.

This is **not** an RP or a CA.

Minimal validation is done on object creation. This is intentional, since a
valid use-case is to create *almost* valid objects to recreate RP bugs.

Similarly, the de-serialisation code contains no crypto validation at all.

## Installation

Python version 3.8 or greater is required.

A package is available on PyPI. You can:

``` sh
python3 -m pip install rpkimancer
```

## Usage

The CLI tools (in the `rpkimancer.cli` package) provide examples of library usage.

The `rpkincant` CLI tool ships with two subcommands:

-   `rpkincant conjure`:

    Creates a simple example repo with a TA and a single sub-ordinate CA.

    All the CRLs and Manifests are generated, along with a ROA and a GBR
    issued by the CA. A TAL for the TA is also generated.

-   `rpkimancer perceive`:

    Reads DER encoded signed objects from disk, and deserialises them based on
    the type indicated by the file extension.

    The result is written to STDOUT by default, in a variety of selectable
    formats.

## Writing Plug-ins

Plug-ins implementing new signed object types can advertise the required
components to `rpkimancer` using the following entry points:

-   `rpkimancer.asn1.modules`:

    A python package containing ASN.1 modules (which must be named `*.asn`)
    to be compiled to python code at run time.

    Each ASN.1 module will end up being available as a `class` in
    `rpkimancer.asn1.mod`.
-   `rpkimancer.sigobj`:

    A `class` inheriting from `rpkimancer.sigobj.base.SignedObject`.
    The `SignedObject` class will usually only need to set the `econtent_cls`
    attribute to a class inheriting from `rpkimancer.sigobj.base.EncapsulatedContent`.

    See the implementations in the `rpkimancer.sigobj` package for examples.

    The entry point is used to map file extensions to implementations by tools
    like `rpkincant perceive`.

-   `rpkimancer.cli`:

    Used to add additional subcommands to the `rpkincant` CLI tool.

    The target should be a `class` inheriting from `rpkimancer.cli.BaseCommand`,
    and implementing the `.init_parser(...)` and `.run(...)` methods.

-   `rpkimancer.cli.conjure`:

    Used to add CLI arguments and object construction code to the `rpkincant conjure`
    subcommand.

    The target should be a class inheriting from `rpkimancer.cli.conjure.ConjurePlugin`,
    and implementing the `.init_parser(...)` and `.run(...)` methods.

## Contributing

Both feature contributions and bug fixes are very welcome.

Please open an issue for discussion before expending energy on an implementation.

Pre-standard RPKI object implementations will not be accepted into the main library.
These should be implemented in a standalone plug-in distribution while still in the
I-D phase.

To set up a development environment:

``` sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r packaging/requirements-dev.txt
```

And to run the tests and other CI jobs locally:

``` sh
tox
```
