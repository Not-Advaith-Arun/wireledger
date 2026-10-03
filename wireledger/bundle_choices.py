"""Explicit count choices bound to the complete already-authenticated bundle."""
import hashlib
from .ledger import canonical


def bundle_choices(bundle,report,value=None):
    guard={'format':'wireledger-bundle-choices/v1','witness':report['witness'],'bundle_sha256':hashlib.sha256(canonical(bundle)).hexdigest()}
    counts=[]
    if value is not None:
        if(not isinstance(value,dict)or set(value)!=set(guard)|{'counts'}or any(value[key]!=expected for key,expected in guard.items())):
            raise ValueError('count choices belong to a different key or changed complete bundle')
        counts=value['counts'];known={row['body']['count']for row in bundle['checkpoints']}
        if(not isinstance(counts,list)or not 1<=len(counts)<=1024 or any(type(n)is not int or n not in known for n in counts)or len(set(counts))!=len(counts)):
            raise ValueError('choose1..1024 distinct supplied signed record counts')
    return {**guard,'counts':list(counts)}
