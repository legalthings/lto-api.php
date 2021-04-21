<?php

declare(strict_types=1);

namespace LTO;

/**
 * Functions for signing and encryption
 */
interface Cryptography
{
    /**
     * Create an encoded signature of a message.
     *
     * @param string $secretkey
     * @param string $message
     * @return string
     */
    public function sign(string $secretkey, string $message): string;

    /**
     * Verify a signature of a message
     *
     * @param string $publickey
     * @param string $signature
     * @param string $message
     * @return boolean
     */
    public function verify(string $publickey, string $signature, string $message): bool;


    /**
     * Encrypt a message for another account.
     * The nonce is appended.
     *
     * @param string $secretkey
     * @param string $publickey
     * @param string $message
     * @return string
     */
    public function encrypt(string $secretkey, string $publickey, string $message): string;

    /**
     * Decrypt a message from another account.
     *
     * @param string $secretkey
     * @param string $publickey
     * @param string $cypherText
     * @return string
     * @throws DecryptException if message can't be decrypted
     */
    public function decrypt(string $secretkey, string $publickey, string $cypherText): string;


    /**
     * Create sign key pair.
     *
     * @param string $seed
     * @return \stdClass
     */
    public function createSignKeys(string $seed): \stdClass;

    /**
     * Get the public key of a secret key for signing.
     *
     * @param string $secretkey
     * @return string
     */
    public function getPublicSignKey(string $secretkey): string;

    /**
     * Create encrypt key pair
     *
     * @param string $seed
     * @return \stdClass
     */
    public function createEncryptKeys(string $seed): \stdClass;

    /**
     * Get the public key of a secret key for encryption.
     *
     * @param string $secretkey
     * @return string
     */
    public function getPublicEncryptKey(string $secretkey): string;

    /**
     * Convert sign keys to encrypt keys.
     *
     * @param object|string $sign
     * @return \stdClass|null
     */
    public function convertSignToEncrypt($sign): ?\stdClass;
}
