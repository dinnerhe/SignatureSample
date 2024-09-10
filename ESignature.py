from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Generate private key
private_key_g = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Write private key to disk with a password "passphrase"
with open("./private_key.pem", "wb") as f:
    f.write(private_key_g.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
    ))


# Write private key to disk with a password "passphrase"
with open("./public_key.pem", "wb") as f:
    f.write(private_key_g.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

# Read private key from disk
with open("./private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=b"passphrase"
    )


# Read public key from disk
with open("./public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read()
    )

# Sign a message
message = b"This is a document"
signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Verify the real signature
try:
    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Verified")
except InvalidSignature:
    print("Verification Failed")


# Verify fake signature
try:
    public_key.verify(
        b"This is a fake signature",
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Verified")
except InvalidSignature:
    print("Verification Failed")

# Verify fake message
    try:
        public_key.verify(
            signature,
            b"Is this a document?",
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Verified")
    except InvalidSignature:
        print("Verification Failed")


