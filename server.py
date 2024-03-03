from flask import Flask, jsonify, request
from datetime import datetime, timedelta, timezone
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# Dictionary to store generated keys
keys = {}


def generate_key():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    return public_key, private_key


def create_jwt(key_id, user_id, issuer, audience, expired=False):
    """
    Create a JWT for the given user_id with specified issuer and audience.
    
    Args:
        key_id: The identifier for the key to be used for encoding the JWT.
        user_id: The subject of the JWT.
        issuer: The issuer of the JWT.
        audience: The intended audience of the JWT.
        expired: Whether the token should be expired (mainly for testing purposes).

    Returns:
        A JWT encoded as a string.
    """
    
    # Set expiry time to 1 hour in the future unless expired is True
    expiry = datetime.now(timezone.utc) + timedelta(hours=1)
    if expired:
        expiry -= timedelta(hours=2)  # Subtract 2 hours so the token is expired by 1 hour

    payload = {
        'sub': user_id,
        'exp': int(expiry.timestamp()),  # Ensure the timestamp is in UTC
        'iss': issuer,
        'aud': audience
    }

    # Retrieve the private key, assuming key_id exists in keys dictionary
    try:
        private_key_pem = keys[key_id]['private_key']
        print("Private Key PEM:", private_key_pem)  # Test case 1: Check if the private key is retrieved successfully
    except KeyError:
        raise ValueError(f"Key ID {key_id} not found.")

    # Load the private key from its PEM-encoded string format
    try:
        private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None, backend=default_backend())
        print("Private key loaded successfully!")  # Test case 2: Verify that the private key is loaded successfully
    except Exception as e:
        print("Error loading private key:", e)  # Test case 2: Check if any exceptions are raised during loading the private key

    # Encode the JWT
    try:
        jwt_token = jwt.encode(payload, private_key, algorithm='RS256', headers={'kid': key_id})
        print("JWT token created successfully:", jwt_token)  # Test case 3: Verify that the JWT token is created successfully
    except Exception as e:
        raise ValueError(f"Failed to encode JWT: {e}")
    
    return jwt_token


def get_jwks():
    jwks = {
        "keys": [{
            "kty": "RSA",
            "kid": kid,
            "use": "sig",
            "alg": "RS256",
            "n": keys[kid]['public_key'].split('\n')[1],
            "e": keys[kid]['public_key'].split('\n')[2]
        } for kid in keys if keys[kid]['expiry'] > datetime.now(timezone.utc)]
    }
    return jwks


@app.route("/.well-known/jwks.json", methods=["GET"])
def getJWKS():
    """
    Returns a JWKS of all JWKs on the server
    """
    return jsonify(get_jwks()), 200


@app.route("/auth", methods=["POST"])
def createJWT():
    """
    Create a JWK and return a corresponding JWT
    """
    user_id = 'user_id'  # Example user ID, replace with actual user ID
    issuer = 'your_issuer'  # Example issuer, replace with actual issuer
    audience = 'your_audience'  # Example audience, replace with actual audience
    
    expired = request.args.get('expired', '').lower() == 'true'  # Check if expired
    key_id = list(keys.keys())[-1] if expired else list(keys.keys())[0]
    jwt_token = create_jwt(key_id, user_id, issuer, audience, expired)

    # Write the JWT to a file
    with open('jwt.txt', 'w') as f:
        f.write(jwt_token)

    return jsonify({'access_token': jwt_token}), 200

@app.route("/", methods=["GET"])
def home():
    """
    Home page route
    """
    return "Welcome to the Gradebot API!", 200

if __name__ == "__main__":
    # Generate initial key pair
    public_key, private_key = generate_key()
    keys['1'] = {'public_key': public_key, 'private_key': private_key,
                 'expiry': datetime.now(timezone.utc) + timedelta(days=30)}

    app.run(port=8080)