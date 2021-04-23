# rpkimancer

> **rpkimancer** /ɑː-piː-keɪ-aɪ-mænsə/
>
> *"One who may be called upon to perform those secret rites and incantations
> necessary for the creation or interpretation of the mystical artifacts of the
> RPKI."*

## About

A library and associated command line utility for quickly creating and reading
arbitrary RPKI signed objects.

The primary motivation was to be able to construct new object types directly
from the ASN.1 `EncapsulatedContentInfo` definition with minimal boilerplate
and zero custom encoding logic.

The base distribution comes with the necessary plumbing to read and write the
currently standardised object types:

- Manifests (RFC6486)
- ROAs (RFC6482)
- Ghostbuster Records (RFC6493)

Additional signed objects can be supported via a plugin system.

This **not** an RP or a CA.

Minimal validation is done on object creation. This is intentional, since a
valid use-case is to create *almost* valid objects to recreate RP bugs.

Similarly, the de-serialisation code contains no crypto validation at all.

## Installation

A package will be on pypi at some stage. In the meantime, you can:

``` sh
pip install git+https://github.com/benmaddison/rpkimancer.git@main#egg=rpkimancer
```
