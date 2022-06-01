# Work-in-progress OIDs Registry

This registry provides `OBJECT IDENTIFIER` values available to early
implementors of RPKI signed object specifications.

The intention is to allow temporary (but still globally unique) OIDs to be
obtained by specification authors and implementors before the point at which an
early-allocation request can be submitted to IANA.

This allows early implementations (and objects created using them) to be shared
without concerns related to squatting on unallocated `OBJECT IDENTIFIER`
values.

This registry is the canonical reference for `OBJECT IDENTIFIER` values
allocated under the `1.3.6.1.4.1.35743.3.1` arc, which has been made available
for this purpose by [Workonline Communications](https://workonline.africa).

The registry source data is available on
[github](https://github.com/benmaddison/rpkimancer/blob/main/object-identifiers/registry.yaml).

To obtain an allocation, please submit a pull-request modifying the registry,
or send an [email](mailto:benm@workonline.africa).

Internet-Draft authors are encouraged to use unique OIDs for each version of
the draft in which the ASN.1 module specification is updated, to facilitate the
co-existence of multi-version implementations.

:::{oid-registry}
:path: ../object-identifiers/registry.yaml
:::
