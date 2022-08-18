__all__ = ['Keypair', 'KeypairType', 'MnemonicLanguageCode']

import re
import binascii
import secrets
import nacl.bindings
import nacl.public

from eth_keys.datatypes import PrivateKey
from bip39 import bip39_to_mini_secret, bip39_generate, bip39_validate
import sr25519
import ed25519_dalek

from typing import Union, Optional

from scalecodec.base import ScaleBytes

from .constants import DEV_PHRASE
from .exceptions import ConfigurationError

from .utils.ss58 import ss58_decode, ss58_encode, is_valid_ss58_address
from .key import extract_derive_path
from .utils.ecdsa_helpers import mnemonic_to_ecdsa_private_key, ecdsa_verify, ecdsa_sign


class KeypairType:
    ED25519 = 0
    SR25519 = 1
    ECDSA = 2


class MnemonicLanguageCode:
    ENGLISH = 'en'
    CHINESE_SIMPLIFIED = 'zh-hans'
    CHINESE_TRADITIONAL = 'zh-hant'
    FRENCH = 'fr'
    ITALIAN = 'it'
    JAPANESE = 'ja'
    KOREAN = 'ko'
    SPANISH = 'es'


class Keypair:

    def __init__(self, ss58_address: str = None, public_key: Union[bytes, str] = None,
                 private_key: Union[bytes, str] = None, ss58_format: int = None, seed_hex: str = None,
                 crypto_type: int = KeypairType.SR25519):
        """
        Allows generation of Keypairs from a variety of input combination, such as a public/private key combination,
        mnemonic or URI containing soft and hard derivation paths. With these Keypairs data can be signed and verified

        Parameters
        ----------
        ss58_address: Substrate address
        public_key: hex string or bytes of public_key key
        private_key: hex string or bytes of private key
        ss58_format: Substrate address format, default to 42 when omitted
        seed_hex: hex string of seed
        crypto_type: Use KeypairType.SR25519 or KeypairType.ED25519 cryptography for generating the Keypair
        """

        self.crypto_type = crypto_type
        self.seed_hex = seed_hex
        self.derive_path = None

        if crypto_type != KeypairType.ECDSA and ss58_address and not public_key:
            public_key = ss58_decode(ss58_address, valid_ss58_format=ss58_format)

        if private_key:

            if type(private_key) is str:
                private_key = bytes.fromhex(private_key.replace('0x', ''))

            if self.crypto_type == KeypairType.SR25519 and len(private_key) != 64:
                raise ValueError('Secret key should be 64 bytes long')

            if self.crypto_type == KeypairType.ECDSA:
                private_key_obj = PrivateKey(private_key)
                public_key = private_key_obj.public_key.to_address()
                ss58_address = private_key_obj.public_key.to_checksum_address()

        if not public_key:
            raise ValueError('No SS58 formatted address or public key provided')

        if type(public_key) is str:
            public_key = bytes.fromhex(public_key.replace('0x', ''))

        if crypto_type == KeypairType.ECDSA:
            if len(public_key) != 20:
                raise ValueError('Public key should be 20 bytes long')
        else:
            if len(public_key) != 32:
                raise ValueError('Public key should be 32 bytes long')

            if not ss58_address:
                ss58_address = ss58_encode(public_key, ss58_format=ss58_format)

        self.ss58_format: int = ss58_format

        self.public_key: bytes = public_key

        self.ss58_address: str = ss58_address

        self.private_key: bytes = private_key

        self.mnemonic = None

    @classmethod
    def generate_mnemonic(cls, words: int = 12, language_code: str = MnemonicLanguageCode.ENGLISH) -> str:
        """
        Generates a new seed phrase with given amount of words (default 12)

        Parameters
        ----------
        words: The amount of words to generate, valid values are 12, 15, 18, 21 and 24
        language_code: The language to use, valid values are: 'en', 'zh-hans', 'zh-hant', 'fr', 'it', 'ja', 'ko', 'es'. Defaults to `MnemonicLanguageCode.ENGLISH`

        Returns
        -------
        str: Seed phrase
        """
        return bip39_generate(words, language_code)

    @classmethod
    def validate_mnemonic(cls, mnemonic: str, language_code: str = MnemonicLanguageCode.ENGLISH) -> bool:
        """
        Verify if specified mnemonic is valid

        Parameters
        ----------
        mnemonic: Seed phrase
        language_code: The language to use, valid values are: 'en', 'zh-hans', 'zh-hant', 'fr', 'it', 'ja', 'ko', 'es'. Defaults to `MnemonicLanguageCode.ENGLISH`

        Returns
        -------
        bool
        """
        return bip39_validate(mnemonic, language_code)

    @classmethod
    def create_from_mnemonic(cls, mnemonic: str, ss58_format=42, crypto_type=KeypairType.SR25519,
                             language_code: str = MnemonicLanguageCode.ENGLISH) -> 'Keypair':
        """
        Create a Keypair for given memonic

        Parameters
        ----------
        mnemonic: Seed phrase
        ss58_format: Substrate address format
        crypto_type: Use `KeypairType.SR25519` or `KeypairType.ED25519` cryptography for generating the Keypair
        language_code: The language to use, valid values are: 'en', 'zh-hans', 'zh-hant', 'fr', 'it', 'ja', 'ko', 'es'. Defaults to `MnemonicLanguageCode.ENGLISH`

        Returns
        -------
        Keypair
        """

        if crypto_type == KeypairType.ECDSA:
            if language_code != MnemonicLanguageCode.ENGLISH:
                raise ValueError("ECDSA mnemonic only supports english")

            private_key = mnemonic_to_ecdsa_private_key(mnemonic)
            keypair = cls.create_from_private_key(private_key, ss58_format=ss58_format, crypto_type=crypto_type)

        else:
            seed_array = bip39_to_mini_secret(mnemonic, "", language_code)

            keypair = cls.create_from_seed(
                seed_hex=binascii.hexlify(bytearray(seed_array)).decode("ascii"),
                ss58_format=ss58_format,
                crypto_type=crypto_type
            )

        keypair.mnemonic = mnemonic

        return keypair

    @classmethod
    def create_from_seed(
            cls, seed_hex: str, ss58_format: Optional[int] = 42, crypto_type=KeypairType.SR25519
    ) -> 'Keypair':
        """
        Create a Keypair for given seed

        Parameters
        ----------
        seed_hex: hex string of seed
        ss58_format: Substrate address format
        crypto_type: Use KeypairType.SR25519 or KeypairType.ED25519 cryptography for generating the Keypair

        Returns
        -------
        Keypair
        """

        if crypto_type == KeypairType.SR25519:
            public_key, private_key = sr25519.pair_from_seed(bytes.fromhex(seed_hex.replace('0x', '')))
        elif crypto_type == KeypairType.ED25519:
            private_key, public_key = ed25519_dalek.ed_from_seed(bytes.fromhex(seed_hex.replace('0x', '')))
        else:
            raise ValueError('crypto_type "{}" not supported'.format(crypto_type))

        public_key = public_key.hex()
        private_key = private_key.hex()

        ss58_address = ss58_encode(f'0x{public_key}', ss58_format)

        return cls(
            ss58_address=ss58_address, public_key=public_key, private_key=private_key,
            ss58_format=ss58_format, crypto_type=crypto_type, seed_hex=seed_hex
        )

    @classmethod
    def create_from_uri(
            cls, suri: str, ss58_format: Optional[int] = 42, crypto_type=KeypairType.SR25519, language_code: str = MnemonicLanguageCode.ENGLISH
    ) -> 'Keypair':
        """
        Creates Keypair for specified suri in following format: `[mnemonic]/[soft-path]//[hard-path]`

        Parameters
        ----------
        suri:
        ss58_format: Substrate address format
        crypto_type: Use KeypairType.SR25519 or KeypairType.ED25519 cryptography for generating the Keypair
        language_code: The language to use, valid values are: 'en', 'zh-hans', 'zh-hant', 'fr', 'it', 'ja', 'ko', 'es'. Defaults to `MnemonicLanguageCode.ENGLISH`

        Returns
        -------
        Keypair
        """

        if suri and suri.startswith('/'):
            suri = DEV_PHRASE + suri

        suri_regex = re.match(r'^(?P<phrase>.[^/]+( .[^/]+)*)(?P<path>(//?[^/]+)*)(///(?P<password>.*))?$', suri)

        suri_parts = suri_regex.groupdict()

        if crypto_type == KeypairType.ECDSA:
            if language_code != MnemonicLanguageCode.ENGLISH:
                raise ValueError("ECDSA mnemonic only supports english")

            private_key = mnemonic_to_ecdsa_private_key(
                mnemonic=suri_parts['phrase'],
                str_derivation_path=suri_parts['path'][1:],
                passphrase=suri_parts['password'] or ''
            )
            derived_keypair = cls.create_from_private_key(private_key, ss58_format=ss58_format, crypto_type=crypto_type)
        else:

            if suri_parts['password']:
                raise NotImplementedError(f"Passwords in suri not supported for crypto_type '{crypto_type}'")

            derived_keypair = cls.create_from_mnemonic(
                suri_parts['phrase'], ss58_format=ss58_format, crypto_type=crypto_type, language_code=language_code
            )

            if suri_parts['path'] != '':

                derived_keypair.derive_path = suri_parts['path']

                if crypto_type not in [KeypairType.SR25519]:
                    raise NotImplementedError('Derivation paths for this crypto type not supported')

                derive_junctions = extract_derive_path(suri_parts['path'])

                child_pubkey = derived_keypair.public_key
                child_privkey = derived_keypair.private_key

                for junction in derive_junctions:

                    if junction.is_hard:

                        _, child_pubkey, child_privkey = sr25519.hard_derive_keypair(
                            (junction.chain_code, child_pubkey, child_privkey),
                            b''
                        )

                    else:

                        _, child_pubkey, child_privkey = sr25519.derive_keypair(
                            (junction.chain_code, child_pubkey, child_privkey),
                            b''
                        )

                derived_keypair = Keypair(public_key=child_pubkey, private_key=child_privkey, ss58_format=ss58_format)

        return derived_keypair

    @classmethod
    def create_from_private_key(
            cls, private_key: Union[bytes, str], public_key: bytes = None, ss58_address: str = None,
            ss58_format: int = None, crypto_type=KeypairType.SR25519
    ) -> 'Keypair':
        """
        Creates Keypair for specified public/private keys
        Parameters
        ----------
        private_key: hex string or bytes of private key
        public_key: hex string or bytes of public key
        ss58_address: Substrate address
        ss58_format: Substrate address format, default = 42
        crypto_type: Use KeypairType.SR25519 or KeypairType.ED25519 cryptography for generating the Keypair

        Returns
        -------
        Keypair
        """

        return cls(
            ss58_address=ss58_address, public_key=public_key, private_key=private_key,
            ss58_format=ss58_format, crypto_type=crypto_type
        )

    def sign(self, data: Union[ScaleBytes, bytes, str]) -> bytes:
        """
        Creates a signature for given data

        Parameters
        ----------
        data: data to sign in `Scalebytes`, bytes or hex string format

        Returns
        -------
        signature in bytes

        """
        if type(data) is ScaleBytes:
            data = bytes(data.data)
        elif data[0:2] == '0x':
            data = bytes.fromhex(data[2:])
        elif type(data) is str:
            data = data.encode()

        if not self.private_key:
            raise ConfigurationError('No private key set to create signatures')

        if self.crypto_type == KeypairType.SR25519:
            signature = sr25519.sign((self.public_key, self.private_key), data)

        elif self.crypto_type == KeypairType.ED25519:
            signature = ed25519_dalek.ed_sign(self.public_key, self.private_key, data)

        elif self.crypto_type == KeypairType.ECDSA:
            signature = ecdsa_sign(self.private_key, data)

        else:
            raise ConfigurationError("Crypto type not supported")

        return signature

    def verify(self, data: Union[ScaleBytes, bytes, str], signature: Union[bytes, str]) -> bool:
        """
        Verifies data with specified signature

        Parameters
        ----------
        data: data to be verified in `Scalebytes`, bytes or hex string format
        signature: signature in bytes or hex string format

        Returns
        -------
        True if data is signed with this Keypair, otherwise False
        """

        if type(data) is ScaleBytes:
            data = bytes(data.data)
        elif data[0:2] == '0x':
            data = bytes.fromhex(data[2:])
        elif type(data) is str:
            data = data.encode()

        if type(signature) is str and signature[0:2] == '0x':
            signature = bytes.fromhex(signature[2:])

        if type(signature) is not bytes:
            raise TypeError("Signature should be of type bytes or a hex-string")

        if self.crypto_type == KeypairType.SR25519:
            crypto_verify_fn = sr25519.verify
        elif self.crypto_type == KeypairType.ED25519:
            crypto_verify_fn = ed25519_dalek.ed_verify
        elif self.crypto_type == KeypairType.ECDSA:
            crypto_verify_fn = ecdsa_verify
        else:
            raise ConfigurationError("Crypto type not supported")

        verified = crypto_verify_fn(signature, data, self.public_key)

        if not verified:
            # Another attempt with the data wrapped, as discussed in https://github.com/polkadot-js/extension/pull/743
            # Note: As Python apps are trusted sources on its own, no need to wrap data when signing from this lib
            verified = crypto_verify_fn(signature, b'<Bytes>' + data + b'</Bytes>', self.public_key)

        return verified

    def encrypt_message(
        self, message: Union[bytes, str], recipient_public_key: bytes, nonce: bytes = secrets.token_bytes(24),
    ) -> bytes:
        """
        Encrypts message with for specified recipient

        Parameters
        ----------
        message: message to be encrypted, bytes or string
        recipient_public_key: recipient's public key
        nonce: the nonce to use in the encryption

        Returns
        -------
        Encrypted message
        """

        if not self.private_key:
            raise ConfigurationError('No private key set to encrypt')
        if self.crypto_type != KeypairType.ED25519:
            raise ConfigurationError('Only ed25519 keypair type supported')
        curve25519_public_key = nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(recipient_public_key)
        recipient = nacl.public.PublicKey(curve25519_public_key)
        private_key = nacl.bindings.crypto_sign_ed25519_sk_to_curve25519(self.private_key + self.public_key)
        sender = nacl.public.PrivateKey(private_key)
        box = nacl.public.Box(sender, recipient)
        return box.encrypt(message if isinstance(message, bytes) else message.encode("utf-8"), nonce)

    def decrypt_message(self, encrypted_message_with_nonce: bytes, sender_public_key: bytes) -> bytes:
        """
        Decrypts message from a specified sender

        Parameters
        ----------
        encrypted_message_with_nonce: message to be decrypted
        sender_public_key: sender's public key

        Returns
        -------
        Decrypted message
        """

        if not self.private_key:
            raise ConfigurationError('No private key set to decrypt')
        if self.crypto_type != KeypairType.ED25519:
            raise ConfigurationError('Only ed25519 keypair type supported')
        private_key = nacl.bindings.crypto_sign_ed25519_sk_to_curve25519(self.private_key + self.public_key)
        recipient = nacl.public.PrivateKey(private_key)
        curve25519_public_key = nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(sender_public_key)
        sender = nacl.public.PublicKey(curve25519_public_key)
        return nacl.public.Box(recipient, sender).decrypt(encrypted_message_with_nonce)

    def encode(self, passphrase: str) -> bytes:
        pass

    def decode(self, passphrase: str, encoded_keypair: bytes):
        pass

    @classmethod
    def import_from_json_file(cls, path_to_json_file, passphrase: str):
        pass

    def export_to_json(self) -> str:
        pass

    def __repr__(self):
        if self.ss58_address:
            return '<Keypair (address={})>'.format(self.ss58_address)
        else:
            return '<Keypair (public_key=0x{})>'.format(self.public_key.hex())
