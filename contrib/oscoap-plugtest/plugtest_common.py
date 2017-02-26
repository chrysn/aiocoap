import os, os.path
import shutil
import tempfile
import json

from aiocoap import oscoap

def get_security_context(testno, role):
    os.makedirs('temp-contexts', exist_ok=True)
    contextcopy = tempfile.mkdtemp(prefix='context-', dir='temp-contexts')
    shutil.copy('./common-context/secret.json', contextcopy)
    shutil.copy('./common-context/settings.json', contextcopy)
    sequence = {
            "used": {"736572766572" if role == 'recipient' else "636c69656e74": testno},
            "seen": {"636c69656e74" if role == 'recipient' else "736572766572": list(range(testno))}
        }
    with open(os.path.join(contextcopy, 'sequence.json'), 'w') as out:
        json.dump(sequence, out)
    print("Temporary context with seqno %d copied to %s"%(testno, contextcopy))
    return oscoap.FilesystemSecurityContext(contextcopy, role=role)

def additional_verify(description, lhs, rhs):
    if lhs == rhs:
        print("Additional verify passed: %s"%description)
    else:
        print("Additional verify failed (%s != %s): %s"%(lhs, rhs, description))
