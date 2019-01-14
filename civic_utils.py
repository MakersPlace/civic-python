import base64
import datetime
import hashlib
import hmac
import json
import uuid
import datetime

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.ec import derive_private_key
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
from django.conf import settings
import jwt
import requests


BASE_URL = "https://api.civic.com/sip/"
AUTH_CODE_PATH = "scopeRequest/authCode"


def create_civic_ext(body):
    body_str = json.dumps(body, separators=(',', ':'))
    message = bytes(body_str, 'utf-8')
    secret = bytes(settings.CIVIC_APP["SECRET"], 'utf-8')
    signature = base64.b64encode(hmac.new(secret, message, digestmod=hashlib.sha256).digest())
    return signature.decode("utf-8")


def make_authorization_header(targetPath, targetMethod, requestBody):
    now_dt = datetime.datetime.now()
    # For some reason when setting this to 3 min, the date time is in the past.
    until = now_dt + datetime.timedelta(seconds=6000*60)
    payload = {
        "method": 'POST',
        "path": AUTH_CODE_PATH,
    }
    content = {
        "jti": str(uuid.uuid4()),
        "iat": now_dt,
        "exp": until,
        "iss": settings.CIVIC_APP["ID"],
        "aud": BASE_URL,
        "sub": settings.CIVIC_APP["ID"],
        "data": payload,
    }
    exp = int(settings.CIVIC_APP["PRIVATE_KEY"], 16)
    key = derive_private_key(exp, SECP256R1(), default_backend())
    headers = {"alg":"ES256","typ":"JWT"}
    token = jwt.encode(content, key, headers=headers, algorithm='ES256').decode("ascii")
    extension = create_civic_ext(requestBody)
    return "Civic {}.{}".format(token, extension)


def get_user_data(jwt_token):
    body = { "authToken": jwt_token, "processPayload": True }
    auth_header = make_authorization_header('scopeRequest/authCode', 'POST', body)
    headers = {
        'Accept': '*/*',
        'Authorization': auth_header,
        'Content-Type': 'application/json',
    }
    url = BASE_URL + 'prod/' + AUTH_CODE_PATH
    url_data = requests.post(url, json=body, headers=headers).json()
    data_url = url_data["data"]
    raw_data = requests.get(data_url).content
    decoded_data = jwt.decode(raw_data, verify=False)['data']  # TODO: Fix this
    secret = bytes.fromhex(settings.CIVIC_APP['SECRET'])
    # First 32 bytes are the key and rest is encrypted data
    key_in_bytes = bytes.fromhex(decoded_data[0:32])
    cipher = Cipher(algorithms.AES(secret), modes.CBC(key_in_bytes), backend=default_backend())
    encodedData = decoded_data[32:]
    encrypted = base64.b64decode(encodedData)
    decryptor = cipher.decryptor()
    decrypted_data_in_bytes = decryptor.update(encrypted) + decryptor.finalize()
     # This ensures that we do not get any other unicode characters after the list.
    beginningIndex = decrypted_data_json.index('[')
    endingIndex = decrypted_data_json.index(']')
    return json.loads(decrypted_data_json)