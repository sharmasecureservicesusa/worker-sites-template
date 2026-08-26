from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from app.config import Settings
from app.security import generate_rsa_key, private_key_from_pem, public_jwk, sha256_hex


@dataclass
class SigningKeys:
    private_key: RSAPrivateKey
    kid: str

    def jwks(self) -> dict:
        return {"keys": [public_jwk(self.private_key, self.kid)]}


def load_signing_keys(settings: Settings) -> SigningKeys:
    if settings.jwt_private_key_pem:
        key = private_key_from_pem(settings.jwt_private_key_pem)
    else:
        key = generate_rsa_key()
    kid = sha256_hex(settings.secret_key)[:16]
    return SigningKeys(private_key=key, kid=kid)
