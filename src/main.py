import base64
import hashlib
import time

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding


def get_open_api_binance_token(app_id, access_key_id, secret_key, data_token):
    # Documentation https://developers.binance.com/docs/mini-program/openservice/signature
    # 1
    http_request_method = "GET"
    # 2
    canonical_uri = f"/mp-api/v1/apps/{app_id}/user-open-data/"
    # 3
    canonical_query_string = f"openData={data_token}"
    # 4
    # 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' == hashlib.sha256(''.encode()).hexdigest()
    request_body = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    # 5
    canonical_request = f"{http_request_method}\n{canonical_uri}\n{canonical_query_string}\n{request_body}"
    canonical_request = hashlib.sha256(canonical_request.encode('utf-8')).digest().hex()

    payload = {
        'iss': access_key_id,
        'dig': canonical_request,
        'ts': int(time.time())
    }
    token = jwt.encode(payload=payload, key=secret_key, algorithm='HS256')
    return token


def decrypt_pkcs1_v15(private_key_string, ciphertext):
    private_key_data = private_key_string.encode('utf-8')
    private_key = serialization.load_pem_private_key(private_key_data, password=None, backend=default_backend())
    decrypted_data = private_key.decrypt(base64.urlsafe_b64decode(ciphertext), padding.PKCS1v15())
    return decrypted_data.decode('utf-8')
