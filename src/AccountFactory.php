<?php

declare(strict_types=1);

namespace LTO;

use LTO\Cryptography\ED25519;
use function sodium_crypto_generichash as blake2b;

/**
 * Create new account (aka wallet)
 */
class AccountFactory
{
    const ADDRESS_VERSION = 0x1;
    
    /**
     * Address scheme
     * @var string
     */
    protected $network;

    /**
     * @var Cryptography
     */
    protected $cryptography;

    /**
     * Class constructor
     *
     * @param int|string $network  'W' or 'T' (1 byte)
     * @param string     $curve    'ed25519', 'secp256k1', or 'secp256r1'
     */
    public function __construct($network, $curve = 'ed25519')
    {
        $this->network = is_int($network) ? chr($network) : substr($network, 0, 1);
        $this->cryptography = static::selectCryptography($curve);
    }

    /**
     * Get cryptography used by the accounts created by this factory.
     */
    public function getCryptography(): Cryptography
    {
        return $this->cryptography;
    }

    /**
     * Create the account seed using several hashing algorithms.
     *
     * @param string $seedText  Brainwallet seed string
     * @param int    $nonce     Incrementing nonce
     * @return string  raw seed (not encoded)
     */
    public function createAccountSeed(string $seedText, int $nonce): string
    {
        $seedBase = pack('La*', $nonce, $seedText);
        $seedHash = sha256(blake2b($seedBase));

        return sha256($seedHash);
    }

    /**
     * Create an address from a public key
     *
     * @param string $publickey  Raw public sign key
     * @return string  raw (not encoded)
     */
    public function createAddress(string $publickey): string
    {
        $publickeyHash = substr(sha256(blake2b($publickey)), 0, 20);
        $prefix = pack('Ca', self::ADDRESS_VERSION, $this->network);

        $base = $prefix . $publickeyHash;
        $chksum = substr(sha256(blake2b($base)), 0, 4);

        return $base . $chksum;
    }
    
    /**
     * Create a new account from a seed
     *
     * @param string $seedText  Brainwallet seed string
     * @param int    $nonce     Incrementing nonce
     * @return Account
     */
    public function seed(string $seedText, int $nonce = 0): Account
    {
        $seed = $this->createAccountSeed($seedText, $nonce);
        
        $account = new Account($this->cryptography);
        
        $account->sign = $this->cryptography->createSignKeys($seed);
        $account->encrypt = $this->cryptography->createEncryptKeys($seed);
        $account->address = $this->createAddress($account->sign->publickey);

        return $account;
    }

    /**
     * Get and verify the raw public and private key.
     *
     * @param array  $keys
     * @param string $type  'sign' or 'encrypt'
     * @return \stdClass
     * @throws InvalidAccountException  if keys don't match
     */
    protected function calcKeys(array $keys, string $type): \stdClass
    {
        if (!isset($keys['secretkey'])) {
            return (object)['publickey' => $keys['publickey']];
        }
        
        $secretkey = $keys['secretkey'];
        
        $publickey = ($type === 'sign')
            ? $this->cryptography->getPublicSignKey($secretkey)
            : $this->cryptography->getPublicEncryptKey($secretkey);
        
        if (isset($keys['publickey']) && $keys['publickey'] !== $publickey) {
            throw new InvalidAccountException("Public {$type} key doesn't match private {$type} key");
        }
        
        return (object)compact('secretkey', 'publickey');
    }

    /**
     * Create an account from base58 encoded keys.
     *
     * @param array|string $keys      All keys (array) or private sign key (string)
     * @param string       $encoding
     * @return Account
     * @throws InvalidAccountException
     */
    public function create($keys, string $encoding = 'base58'): Account
    {
        $data = self::decodeRecursive($keys, $encoding);
        
        if (is_string($data)) {
            $data = ['sign' => ['secretkey' => $data]];
        }
        
        $account = new Account($this->cryptography);
        
        $account->sign = isset($data['sign']) ? $this->calcKeys($data['sign'], 'sign') : null;

        $account->encrypt = isset($data['encrypt'])
            ? $this->calcKeys($data['encrypt'], 'encrypt')
            : (isset($account->sign) ? $this->cryptography->convertSignToEncrypt($account->sign) : null);

        $account->address = isset($data['address'])
            ? $data['address']
            : ($account->sign !== null ? $this->createAddress($account->sign->publickey) : null);

        $this->assertIsValid($account);

        return $account;
    }
    
    /**
     * Create an account from public keys.
     *
     * @param string|null $sign
     * @param string|null $encrypt
     * @param string      $encoding  Encoding of keys 'raw', 'base58' or 'base64'
     * @return Account
     * @throws InvalidAccountException
     */
    public function createPublic(?string $sign = null, ?string $encrypt = null, string $encoding = 'base58'): Account
    {
        $data = [];
        
        if (isset($sign)) {
            $data['sign'] = ['publickey' => $sign];
        }
        
        if (isset($encrypt)) {
            $data['encrypt'] = ['publickey' => $encrypt];
        }
        
        return $this->create($data, $encoding);
    }


    /**
     * Assert that the account is valid and has an address on this network.
     *
     * @param Account $account
     * @throws InvalidAccountException
     */
    public function assertIsValid(Account $account): void
    {
        $this->assertIsValidAddress($account);
        $this->assertKeysMatch($account);
    }

    /**
     * Assert the address based on the encrypt key and check the network.
     *
     * @param Account $account
     * @throws InvalidAccountException
     */
    protected function assertIsValidAddress(Account $account): void
    {
        if ($account->address === null) {
            return;
        }

        ['network' => $network] = unpack('Cversion/anetwork', $account->address);

        if ($network != $this->network) {
            throw new InvalidAccountException("Address is of network '$network', not of '{$this->network}'");
        }

        if (isset($account->sign) && $account->address !== $this->createAddress($account->sign->publickey)) {
            throw new InvalidAccountException("Address doesn't match sign key");
        }
    }

    /**
     * Assert the that encrypt and sign keys have had the same seed and public/private keys match.
     *
     * @param Account $account
     * @throws InvalidAccountException
     */
    protected function assertKeysMatch(Account $account): void
    {
        $cryptography = $account->getCryptography();

        if (isset($account->sign->secretkey) &&
            $account->sign->publickey !== $cryptography->getPublicSignKey($account->sign->secretkey)
        ) {
            throw new InvalidAccountException("Public sign key doesn't match private sign key");
        }

        if (isset($account->encrypt->secretkey) &&
            $account->encrypt->publickey !== $cryptography->getPublicEncryptKey($account->encrypt->secretkey)
        ) {
            throw new InvalidAccountException("Public encrypt key doesn't match private encrypt key");
        }

        $convertedEncryptKeys = $cryptography->convertSignToEncrypt($account->sign);

        if ($convertedEncryptKeys !== null &&
            isset($account->encrypt->publickey) &&
            isset($convertedEncryptKeys->publickey) &&
            $account->encrypt->publickey !== $convertedEncryptKeys->publickey
        ) {
            throw new InvalidAccountException("Sign key doesn't match encrypt key");
        }
    }


    /**
     * Base58 or base64 decode, recursively
     *
     * @param string|array $data
     * @param string       $encoding  'raw', 'base58' or 'base64'
     * @return string|array
     */
    protected static function decodeRecursive($data, string $encoding = 'base58')
    {
        if ($encoding === 'raw') {
            return $data;
        }

        if (is_array($data)) {
            return array_map(function ($item) use ($encoding) {
                return self::decodeRecursive($item, $encoding);
            }, $data);
        }

        return decode($data, $encoding);
    }

    /**
     * Select a cryptography method / curve.
     *
     * @param string $curve
     * @return Cryptography
     */
    protected static function selectCryptography(string $curve): Cryptography
    {
        switch ($curve) {
            case 'ed25519':
                return new ED25519();
            default:
                throw new \InvalidArgumentException("Unsupported curve '$curve'");
        }
    }
}
