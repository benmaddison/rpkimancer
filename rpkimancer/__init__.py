import contextlib
import hashlib
import urllib.request

from .rpki_rsu import RpkiSignedURIList_2021

SHA256 = (2, 16, 840, 1, 101, 3, 4, 2)
DIGEST_ALGORITHMS = {SHA256: hashlib.sha256}


class EncapsulatedContentInfo:

    content_type = None
    content_syntax = None

    def __init__(self, **kwargs):
        with self.constructed(kwargs) as instance:
            self.data = instance.get_val()

    @contextlib.contextmanager
    def constructed(self, data=None):
        if data is None:
            data = self.data
        try:
            self.content_syntax.set_val(data)
            yield self.content_syntax
        finally:
            self.content_syntax.reset_val()

    def to_asn1(self):
        with self.constructed() as instance:
            return instance.to_asn1()

    def to_der(self):
        with self.constructed() as instance:
            return instance.to_der()


class RpkiSignedURIList(EncapsulatedContentInfo):

    content_type = RpkiSignedURIList_2021.ct_rpkiSignedURIList
    content_syntax = RpkiSignedURIList_2021.RpkiSignedURIList

    def __init__(self, *uris, digest_algorithm=SHA256, **kwargs):
        uri_list = list()
        alg = DIGEST_ALGORITHMS[digest_algorithm]
        for uri in uris:
            hasher = alg()
            with urllib.request.urlopen(uri) as response:
                data = response.read()
            length = len(data)
            hasher.update(data)
            digest = hasher.digest()
            uri_list.append(dict(uri=uri, size=length, hash=digest))
        super().__init__(digestAlgorithm=dict(algorithm=digest_algorithm),
                              uriList=uri_list,
                              **kwargs)
