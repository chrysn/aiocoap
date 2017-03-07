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
        # this needs to be messed with early, as key properties are derived
        # from this data
        if testno == 10 and role == 'sender':
            assert settingsdata['sender-id'] == '636C69656E74'
            settingsdata['sender-id'] = '116C69656E74'
        if testno == 13 and role == 'sender':
            settingsdata['recipient-id'] = '116572766572'

        json.dump(settingsdata, out)
    sequence = {
            "used": {(settingsdata['recipient-id'] if role == 'recipient' else settingsdata['sender-id']).lower(): testno},
            "seen": {(settingsdata['sender-id'] if role == 'recipient' else settingsdata['recipient-id']).lower(): list(range(testno))}
        }
    with open(os.path.join(contextcopy, 'sequence.json'), 'w') as out:
        if testno == 14 and role == 'sender':
            sequence["used"][list(sequence["used"].keys())[0]] = 0;
        if testno == 15 and role == 'sender':
            sequence["seen"][list(sequence["seen"].keys())[0]] = [65];
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
    if testno == 11 and role == 'sender':
        secctx.other_key = bytes((11,)) + secctx.other_key[1:]
    if testno == 12 and role == 'sender':
        assert hexlify(secctx.other_iv) == b'58f91a5cdff4f5'
        secctx.other_iv = unhexlify(b'11f91a5cdff4f5')


    original_extract_external_aad = secctx._extract_external_aad
    def _extract_extenal_aad(message, i_am_sender, request_partiv=None):
        result = original_extract_external_aad(message, i_am_sender, request_partiv)
        print("Verify: External AAD: %s"%(result,))
        return result
    secctx._extract_external_aad = _extract_extenal_aad

    return secctx

def additional_verify(description, lhs, rhs):
    if lhs == rhs:
        print("Additional verify passed: %s"%description)
    else:
        print("Additional verify failed (%s != %s): %s"%(lhs, rhs, description))
