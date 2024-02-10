# Binance OpenAPI Signature Authentication and Data Retrieval

This Python script showcases the generation of a Binance Open API signature for authentication purposes and subsequent retrieval of user data. It utilizes the `get_open_api_binance_token` function to acquire the necessary token, which is then utilized in the header of a request sent to a designated endpoint. Upon receiving the response, user data is extracted and decrypted using a private key.


## Helpful Links:
- [Binance Open Service API Documentation](https://developers.binance.com/docs/mini-program/openservice/open-service)
- [Binance Open Data API Documentation](https://developers.binance.me/docs/mini-program/openservice/get-open-data)
- [Binance Open Service Signature Documentation](https://developers.binance.com/docs/mini-program/openservice/signature)

## Functionality Overview:

1. **Authentication Signature Generation:**
    - The `get_open_api_binance_token` function constructs a signature following Binance Developer documentation specifications.
    - It utilizes various parameters such as HTTP request method, URI, query string, and request body to create a canonical request string.
    - The canonical request string is then hashed and encoded into a JWT payload.

2. **Data Retrieval and Decryption:**
    - After obtaining the token, it is set in the 'X-Mp-Open-Api-Token' header.
    - A request is sent to the designated endpoint with the token in the header.
    - Upon receiving the response, user data is extracted.
    - The user data is decrypted using the provided private key.

## Usage Example:

```python
import base64
import hashlib
import time

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding


# Function to decrypt ciphertext with private key
def decrypt_pkcs1_v15(private_key_string, ciphertext):
    private_key_data = private_key_string.encode('utf-8')
    private_key = serialization.load_pem_private_key(private_key_data, password=None, backend=default_backend())
    decrypted_data = private_key.decrypt(base64.urlsafe_b64decode(ciphertext), padding.PKCS1v15())
    return decrypted_data.decode('utf-8')

# Function to generate Binance OpenAPI token
def get_open_api_binance_token(app_id, access_key_id, secret_key, data_token):
    # 1. Construct HTTP request method (HTTPRequestMethod)
    http_request_method = "GET"

    # 2. Construct the URI parameter (CanonicalURI)
    canonical_uri = f"/mp-api/v1/apps/{app_id}/user-open-data/"

    # 3. Construct CanonicalQueryString
    canonical_query_string = f"openData={data_token}"

    # 4. The body in the body (RequestPayload)
    # 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' == hashlib.sha256(''.encode()).hexdigest()
    request_body = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

    # 5. Hash the constructed canonical request string
    canonical_request = f"{http_request_method}\n{canonical_uri}\n{canonical_query_string}\n{request_body}"
    canonical_request = hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()

    # 6. Set the encoded string to the dig field of the JWT payload
    payload = {
        'iss': access_key_id,
        'dig': canonical_request,
        'ts': int(time.time())
    }
    token = jwt.encode(payload=payload, key=secret_key, algorithm='HS256')
    return token

# Obtain the X-Mp-Open-Api-Token from get_open_api_binance_token function
open_api_token = get_open_api_binance_token(app_id, access_key_id, secret_key, data_token)

# Set the X-Mp-Open-Api-Token header
headers = {'X-Mp-Open-Api-Token': open_api_token}

# Send request to the endpoint
endpoint = f"https://dip-cb.binanceapi.com/mp-api/v1/apps/{app_id}/user-open-data?openData={token}"
response = requests.get(endpoint, headers=headers)

# Extract user data from the response JSON
user_data = response.get('data', {}).get('userData')

# Decrypt user data with private key
user_openid = decrypt_pkcs1_v15(private_key_string=private_key, ciphertext=user_data)
