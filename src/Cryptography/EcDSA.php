<?php

declare(strict_types=1);

namespace LTO\Cryptography;

use LTO\Cryptography;

use Mdanter\Ecc\Crypto\Key\PrivateKeyInterface;
use Mdanter\Ecc\Crypto\Key\PublicKeyInterface;
use Mdanter\Ecc\Crypto\Signature\Signer;
use Mdanter\Ecc\Crypto\Signature\SignHasher;
use Mdanter\Ecc\Curves\NamedCurveFp;
use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Math\GmpMathInterface;
use Mdanter\Ecc\Primitives\GeneratorPoint;
use Mdanter\Ecc\Random\RandomGeneratorFactory;
use Mdanter\Ecc\Random\RandomNumberGeneratorInterface;
use Mdanter\Ecc\Serializer\PrivateKey\DerPrivateKeySerializer;
use Mdanter\Ecc\Serializer\PublicKey\DerPublicKeySerializer;
use Mdanter\Ecc\Serializer\Signature\DerSignatureSerializer;

/**
 * EcDSA signing using ECC library.
 * Encryption using ECDH is not (yet) supported.
 */
class EcDSA implements Cryptography
{
    /** @var GmpMathInterface */
    protected $adapter;

    /** @var NamedCurveFp */
    protected $curve;

    /** @var GeneratorPoint */
    protected $generator;

    /** @var RandomNumberGeneratorInterface */
    protected $random;


    /**
     * EcDSA constructor.
     *
     * @param string $curve
     */
    public function __construct(
        GmpMathInterface $adapter,
        NamedCurveFp $curve,
        GeneratorPoint $generator,
        RandomNumberGeneratorInterface $random
    ) {
        $this->adapter = $adapter;
        $this->curve = $curve;
        $this->generator = $generator;
        $this->random = $random;
    }

    /**
     * @inheritDoc
     */
    public function sign(string $secretkey, string $message): string
    {
        $signatureSerializer = new DerSignatureSerializer();

        $hasher = new SignHasher('sha256', $this->adapter);
        $hash = $hasher->makeHash($message, $this->generator);
        $randomK = $this->random->generate($this->generator->getOrder());

        $signer = new Signer($this->adapter);
        $key = $this->parsePrivateKey($secretkey);

        $signature = $signer->sign($key, $hash, $randomK);

        return $signatureSerializer->serialize($signature);
    }

    /**
     * @inheritDoc
     */
    public function verify(string $publicKey, string $signature, string $message): bool
    {
        $signatureSerializer = new DerSignatureSerializer();
        $sig = $signatureSerializer->parse($signature);

        $hasher = new SignHasher('sha256', $this->adapter);
        $hash = $hasher->makeHash($message, $this->generator);

        $signer = new Signer($this->adapter);
        $key = $this->parsePublicKey($publicKey);

        return $signer->verify($key, $sig, $hash);
    }


    /**
     * @inheritDoc
     */
    public function encrypt(string $secretkey, string $publicKey, string $message): string
    {
        throw new \BadMethodCallException("Encryption isn't supported for EcDSA");
    }

    /**
     * @inheritDoc
     */
    public function decrypt(string $secretkey, string $publicKey, string $cypherText): string
    {
        throw new \BadMethodCallException("Encryption isn't supported for EcDSA");
    }


    /**
     * @inheritDoc
     *
     * @todo This creates a random account. How to create one from seed.
     * @todo Is this private key the secret key ???
     * @todo Do we use DER serialization implicitly for ED25519 ???
     */
    public function createSignKeys(string $seed): \stdClass
    {
        $privateSerializer = new DerPrivateKeySerializer($this->adapter);
        $publicSerializer = new DerPublicKeySerializer($this->adapter);

        $key = $this->generator->createPrivateKey();
        $publickey = $publicSerializer->serialize($key->getPublicKey());
        $secretkey = $privateSerializer->serialize($key);

        return (object)compact('publickey', 'secretkey');
    }

    /**
     * @inheritDoc
     */
    public function getPublicSignKey(string $secretkey): string
    {
        $publicSerializer = new DerPublicKeySerializer($this->adapter);
        $key = $this->parsePrivateKey($secretkey);

        return $publicSerializer->serialize($key->getPublicKey());
    }

    /**
     * @inheritDoc
     */
    public function createEncryptKeys(string $seed): \stdClass
    {
        return (object)[];
    }

    /**
     * @inheritDoc
     */
    public function getPublicEncryptKey(string $secretkey): string
    {
        throw new \BadMethodCallException("Encryption isn't supported for EcDSA");
    }

    /**
     * @inheritDoc
     */
    public function convertSignToEncrypt($sign): ?\stdClass
    {
        return null;
    }


    /**
     * Parse the private key from DES format.
     */
    protected function parsePrivateKey(string $secretkey): PrivateKeyInterface
    {
        $privateSerializer = new DerPrivateKeySerializer($this->adapter);

        return $privateSerializer->parse($secretkey);
    }

    /**
     * Parse the public key from DES format.
     */
    protected function parsePublicKey(string $publickey): PublicKeyInterface
    {
        $privateSerializer = new DerPublicKeySerializer($this->adapter);

        return $privateSerializer->parse($publickey);
    }


    /**
     * Factory method.
     *
     * @param string $curve
     * @return self
     */
    public static function forCurve(string $curve): self
    {
        if (!class_exists(EccFactory::class)) {
            throw new \LogicException("Please install the mdanter/ecc library to use '$curve'");
        }

        return new self(
            EccFactory::getAdapter(),
            self::selectCurve($curve),
            self::selectGenerator($curve),
            RandomGeneratorFactory::getRandomGenerator()
        );
    }

    /**
     * Get ECC implementation for a specific curve.
     *
     * @param string $curve
     * @return NamedCurveFp
     */
    protected static function selectCurve(string $curve): NamedCurveFp
    {
        switch ($curve) {
            case 'secp112r1': return EccFactory::getSecgCurves()->curve112r1();
            case 'secp192k1': return EccFactory::getSecgCurves()->curve192k1();
            case 'secp256k1': return EccFactory::getSecgCurves()->curve256k1();
            case 'secp256r1': return EccFactory::getSecgCurves()->curve256r1();
            case 'secp384r1': return EccFactory::getSecgCurves()->curve384r1();
            case 'nistp192':  return EccFactory::getNistCurves()->curve192();
            case 'nistp224':  return EccFactory::getNistCurves()->curve224();
            case 'nistp256':  return EccFactory::getNistCurves()->curve256();
            case 'nistp384':  return EccFactory::getNistCurves()->curve384();
            case 'nistp521':  return EccFactory::getNistCurves()->curve521();
            default:
                throw new \InvalidArgumentException("Unsupported curve '$curve'");
        }
    }

    /**
     * Get ECC generator for a specific curve.
     *
     * @param string $curve
     * @return GeneratorPoint
     */
    protected static function selectGenerator(string $curve): GeneratorPoint
    {
        switch ($curve) {
            case 'secp112r1': return EccFactory::getSecgCurves()->generator112r1();
            case 'secp192k1': return EccFactory::getSecgCurves()->generator192k1();
            case 'secp256k1': return EccFactory::getSecgCurves()->generator256k1();
            case 'secp256r1': return EccFactory::getSecgCurves()->generator256r1();
            case 'secp384r1': return EccFactory::getSecgCurves()->generator384r1();
            case 'nistp192':  return EccFactory::getNistCurves()->generator192();
            case 'nistp224':  return EccFactory::getNistCurves()->generator224();
            case 'nistp256':  return EccFactory::getNistCurves()->generator256();
            case 'nistp384':  return EccFactory::getNistCurves()->generator384();
            case 'nistp521':  return EccFactory::getNistCurves()->generator521();
            default:
                throw new \InvalidArgumentException("Unsupported curve '$curve'");
        }
    }
}
