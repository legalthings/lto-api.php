<?php

declare(strict_types=1);

namespace LTO\Cryptography;

use LTO\Cryptography;
use LTO\DecryptException;
use SodiumException;

// ED25519 sign functions
use function sodium_crypto_sign_detached as ed25519_sign;
use function sodium_crypto_sign_verify_detached as ed25519_verify;
use function sodium_crypto_sign_seed_keypair as ed25519_seed_keypair;
use function sodium_crypto_sign_publickey as ed25519_publickey;
use function sodium_crypto_sign_secretkey as ed25519_secretkey;
use function sodium_crypto_sign_publickey_from_secretkey as ed25519_publickey_from_secretkey;

// X25519 encrypt functions
use function sodium_crypto_box_keypair_from_secretkey_and_publickey as x25519_keypair;
use function sodium_crypto_box as x25519_encrypt;
use function sodium_crypto_box_open as x25519_decrypt;
use function sodium_crypto_box_seed_keypair as x25519_seed_keypair;
use function sodium_crypto_box_publickey as x25519_publickey;
use function sodium_crypto_box_secretkey as x25519_secretkey;
use function sodium_crypto_box_publickey_from_secretkey as x25519_publickey_from_secretkey;

// Convert ED25519 keys to X25519 keys
use function sodium_crypto_sign_ed25519_pk_to_curve25519 as ed25519_to_x25519_publickey;
use function sodium_crypto_sign_ed25519_sk_to_curve25519 as ed25519_to_x25519_secretkey;

/**
 * ED25519 signing and X25519 encryption
 */
class ED25519 implements Cryptography
{
    /**
     * Get a random nonce.
     * @codeCoverageIgnore
     *
     * @return string
     */
    protected function getNonce()
    {
        return random_bytes(SODIUM_CRYPTO_BOX_NONCEBYTES);
    }

    /**
     * @inheritDoc
     */
    public function sign(string $secretkey, string $message): string
    {
        return ed25519_sign($message, $secretkey);
    }

    /**
     * @inheritDoc
     */
    public function verify(string $publicKey, string $signature, string $message): bool
    {
        return strlen($signature) === SODIUM_CRYPTO_SIGN_BYTES &&
            strlen($publicKey) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES &&
            ed25519_verify($signature, $message, $publicKey);
    }


    /**
     * @inheritDoc
     */
    public function encrypt(string $secretkey, string $publicKey, string $message): string
    {
        $encryptionKey = x25519_keypair($secretkey, $publicKey);
        $nonce = $this->getNonce();

        return x25519_encrypt($message, $nonce, $encryptionKey) . $nonce;
    }

    /**
     * @inheritDoc
     */
    public function decrypt(string $secretkey, string $publicKey, string $cypherText): string
    {
        $encryptedMessage = substr($cypherText, 0, -24);
        $nonce = substr($cypherText, -24);

        try {
            $encryptionKey = x25519_keypair($secretkey, $publicKey);
            $message = x25519_decrypt($encryptedMessage, $nonce, $encryptionKey);
        } catch (SodiumException $exception) { // @codeCoverageIgnoreStart
            throw new DecryptException("Failed to decrypt message", 0, $exception);
        } // @codeCoverageIgnoreEnd

        if ($message === false) {
            throw new DecryptException("Failed to decrypt message");
        }

        return $message;
    }


    /**
     * @inheritDoc
     */
    public function createSignKeys(string $seed): \stdClass
    {
        $keypair = ed25519_seed_keypair($seed);
        $publickey = ed25519_publickey($keypair);
        $secretkey = ed25519_secretkey($keypair);

        return (object)compact('publickey', 'secretkey');
    }

    /**
     * @inheritDoc
     */
    public function getPublicSignKey(string $secretkey): string
    {
        return ed25519_publickey_from_secretkey($secretkey);
    }

    /**
     * @inheritDoc
     */
    public function createEncryptKeys(string $seed): \stdClass
    {
        $keypair = x25519_seed_keypair($seed);
        $publickey = x25519_publickey($keypair);

        $insecureSecretkey = x25519_secretkey($keypair);
        $secretkey = $this->applyEncryptSecretBitmask($insecureSecretkey);

        return (object)compact('publickey', 'secretkey');
    }

    /**
     * @inheritDoc
     */
    public function getPublicEncryptKey(string $secretkey): string
    {
        return x25519_publickey_from_secretkey($secretkey);
    }

    /**
     * Apply a bitmask for a X25519 secret key.
     * The masked secret key works with the same public key.
     *
     * @return string
     */
    protected function applyEncryptSecretBitmask(string $secretkey): string
    {
        $bytes = unpack('C*', $secretkey); // 1-based array

        $bytes[1] &= 248;
        $bytes[32] &= 127;
        $bytes[32] |= 64;

        return pack('C*', ...$bytes);
    }

    /**
     * Convert sign keys to encrypt keys.
     *
     * @param object|string $sign
     * @return \stdClass
     * @throws SodiumException
     */
    public function convertSignToEncrypt($sign): \stdClass
    {
        $encrypt = (object)[];

        if (isset($sign->secretkey)) {
            $encrypt->secretkey = ed25519_to_x25519_secretkey($sign->secretkey);
            // Bitmask is already applied by libsodium
        }

        if (isset($sign->publickey)) {
            $encrypt->publickey = ed25519_to_x25519_publickey($sign->publickey);
        }

        return $encrypt;
    }
}
