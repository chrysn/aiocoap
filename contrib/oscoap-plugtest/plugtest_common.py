import os, os.path
import tempfile
import json
from binascii import hexlify, unhexlify

from aiocoap import oscoap

def get_security_context(testno, role):
    os.makedirs('temp-contexts', exist_ok=True)
    contextcopy = tempfile.mkdtemp(prefix='context-', dir='temp-contexts')
    secretdata = json.load(open('./common-context/secret.json'))
    with open(os.path.join(contextcopy, 'secret.json'), 'w') as out:
        json.dump(secretdata, out)
    settingsdata = json.load(open('./common-context/settings.json'))
    with open(os.path.join(contextcopy, 'settings.json'), 'w') as out:
        if testno == 10 and role == 'sender':
            # this needs to be messed with early, as key properties are derived
            # from this data
            print(settingsdata)
            assert settingsdata['sender-id'] == '636C69656E74'
            settingsdata['sender-id'] = '116C69656E74'
        json.dump(settingsdata, out)
    sequence = {
            "used": {(settingsdata['recipient-id'] if role == 'recipient' else settingsdata['sender-id']).lower(): testno},
            "seen": {(settingsdata['sender-id'] if role == 'recipient' else settingsdata['recipient-id']).lower(): list(range(testno))}
        }
    with open(os.path.join(contextcopy, 'sequence.json'), 'w') as out:
        json.dump(sequence, out)
    print("Temporary context with seqno %d copied to %s"%(testno, contextcopy))
    secctx = oscoap.FilesystemSecurityContext(contextcopy, role=role)

    # this needs to be messed with late, as it is not explicit in the context
    # files
    if testno == 8 and role == 'sender':
        secctx.my_key = bytes((11,)) + secctx.my_key[1:]
    if testno == 9 and role == 'sender':
        assert hexlify(secctx.my_iv) == b'e828a479d088c4'
        secctx.my_iv = unhexlify(b'1128a479d088c4')

    return secctx

def additional_verify(description, lhs, rhs):
    if lhs == rhs:
        print("Additional verify passed: %s"%description)
    else:
        print("Additional verify failed (%s != %s): %s"%(lhs, rhs, description))
