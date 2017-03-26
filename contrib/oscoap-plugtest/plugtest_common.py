import os, os.path
import tempfile
import json
from binascii import hexlify, unhexlify

from aiocoap import oscoap

contextdir = os.path.dirname(__file__) + '/common-context/'

def get_security_context(testno, role):
    os.makedirs('temp-contexts', exist_ok=True)
    contextcopy = tempfile.mkdtemp(prefix='context-', dir='temp-contexts')
    secretdata = json.load(open(contextdir + 'secret.json'))
    with open(os.path.join(contextcopy, 'secret.json'), 'w') as out:
        json.dump(secretdata, out)
    settingsdata = json.load(open(contextdir + 'settings.json'))
    with open(os.path.join(contextcopy, 'settings.json'), 'w') as out:
        # this needs to be messed with early, as key properties are derived
        # from this data
        if role == 'client':
            if testno == 10:
                assert settingsdata['client-sender-id_hex'] == '636C69656E74'
                settingsdata['client-sender-id_hex'] = '116C69656E74'
            if testno == 13:
                settingsdata['server-sender-id_hex'] = '116572766572'

        json.dump(settingsdata, out)
    sequence = {
            "used": {(settingsdata['server-sender-id_hex'] if role == 'server' else settingsdata['client-sender-id_hex']).lower(): testno},
            "seen": {(settingsdata['client-sender-id_hex'] if role == 'server' else settingsdata['server-sender-id_hex']).lower(): list([testno - 1])}
        }
    with open(os.path.join(contextcopy, 'sequence.json'), 'w') as out:
        if role == 'client':
            if testno == 14:
                sequence["used"][list(sequence["used"].keys())[0]] = 0;
            if testno == 15:
                sequence["seen"][list(sequence["seen"].keys())[0]] = [65];
        json.dump(sequence, out)
    print("Temporary context with seqno %d copied to %s"%(testno, contextcopy))
    secctx = oscoap.FilesystemSecurityContext(contextcopy, role=role)

    # this needs to be messed with late, as it is not explicit in the context
    # files
    if role == 'client':
        if testno == 8:
            secctx.sender_key = bytes((11,)) + secctx.sender_key[1:]
        if testno == 9:
            # the derived keys have changed since the plugtest specification,
            # but the modified one is still a bad one
            # assert hexlify(secctx.sender_iv) == b'e828a479d088c4'
            secctx.sender_iv = unhexlify(b'1128a479d088c4')
        if testno == 11:
            secctx.recipient_key = bytes((11,)) + secctx.recipient_key[1:]
        if testno == 12:
            assert hexlify(secctx.recipient_iv) == b'58f91a5cdff4f5'
            secctx.recipient_iv = unhexlify(b'11f91a5cdff4f5')


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
