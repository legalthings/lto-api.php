<?php

declare(strict_types=1);

namespace LTO;

use function sodium_crypto_generichash as blake2b;

/**
 * Abstract base class for transactions.
 */
abstract class Transaction implements \JsonSerializable
{
    protected const TYPES = [
        4 => Transaction\Transfer::class,
        8 => Transaction\Lease::class,
        9 => Transaction\CancelLease::class,
        11 => Transaction\MassTransfer::class,
        15 => Transaction\Anchor::class,
        16 => Transaction\Association::class,
        17 => Transaction\RevokeAssociation::class,
        18 => Transaction\Sponsor::class,
        19 => Transaction\CancelSponsor::class,
    ];


    /** @var string */
    public $id;

    /** @var string|null */
    public $sender = null;

    /** @var string|null */
    public $senderPublicKey = null;

    /** @var int|null epoch in milliseconds */
    public $timestamp = null;

    /** @var int */
    public $fee;

    /** @var string[] */
    public $proofs = [];

    /** @var int|null */
    public $height;

    /**
     * Get binary representation of the unsigned transaction.
     */
    abstract public function toBinary(): string;

    /**
     * Get the transaction id.
     * Generate it from the binary if the id is unknown.
     *
     * @return string
     */
    public function getId(): string
    {
        return $this->id ?? blake2b($this->toBinary());
    }

    /**
     * Sign this transaction.
     *
     * @param Account $account
     * @return $this
     * @throws \RuntimeException if account secret sign key is not set
     */
    public function signWith(Account $account): self
    {
        if ($this->sender === null) {
            $this->sender = $account->getAddress();
            $this->senderPublicKey = $account->getPublicSignKey();
        }

        if ($this->timestamp === null) {
            $this->timestamp = time() * 1000;
        }

        $this->proofs[] = $account->sign($this->toBinary());

        return $this;
    }

    /**
     * Get the network id based on the sender address.
     */
    public function getNetwork(): string
    {
        if ($this->sender === null) {
            throw new \BadMethodCallException("Sender not set");
        }

        ['network' => $network] = unpack('Cversion/anetwork', decode($this->sender, 'base58'));

        return $network;
    }

    /**
     * Broadcast transaction to a node.
     *
     * @param PublicNode $node
     * @return static
     */
    final public function broadcastTo(PublicNode $node): self
    {
        return $node->broadcast($this);
    }

    /**
     * Is the transaction signed?
     */
    public function isSigned(): bool
    {
        return $this->proofs !== [];
    }


    /**
     * Get data for JSON serialization.
     *
     * @return array<string,mixed>
     */
    public function jsonSerialize(): array
    {
        $data = ['type' => 0, 'version' => 0] + get_public_properties($this);

        if ($data['id'] === null) {
            unset($data['id']);
        }
        if ($data['height'] === null) {
            unset($data['height']);
        }

        return $data;
    }

    /**
     * Assert that there are no missing keys in the data.
     *
     * @throws \InvalidArgumentException
     */
    protected static function assertNoMissingKeys(array $data, array $optionalKeys = ['id', 'height']): void
    {
        $requiredKeys = array_diff(array_keys(get_class_vars(get_called_class())), $optionalKeys);
        $missingKeys = array_diff($requiredKeys, array_keys($data));

        if ($missingKeys !== []) {
            throw new \InvalidArgumentException("Invalid data, missing keys: " . join(', ', $missingKeys));
        }
    }

    /**
     * Assert that the tx type and version of the data matches the expected values.
     *
     * @throws \InvalidArgumentException
     */
    protected static function assertTypeAndVersion(array $data, int $type, int $version): void
    {
        if (isset($data['type']) && (int)$data['type'] !== $type) {
            throw new \InvalidArgumentException("Invalid type {$data['type']}, should be {$type}");
        }

        if (isset($data['version']) && (int)$data['version'] !== $version) {
            throw new \InvalidArgumentException("Invalid version {$data['version']}, should be {$version}");
        }
    }

    /**
     * Create a Transaction object from data.
     *
     * @param array $data
     * @return static
     */
    public static function fromData(array $data)
    {
        if (get_called_class() !== __CLASS__) {
            throw new \LogicException(__CLASS__ . " must override the fromData method"); // @codeCoverageIgnore
        }

        if (!isset($data['type'])) {
            throw new \InvalidArgumentException("Invalid data; type field is missing");
        }

        $class = self::TYPES[$data['type']] ?? null;

        if ($class === null) {
            throw new \InvalidArgumentException("Unsupported transaction type {$data['type']}");
        }

        return $class::fromData($data);
    }

    /**
     * Factory method to create and populate a transaction.
     * May only be called from a child class.
     *
     * @param array $data
     * @return object
     * @throws \ReflectionException
     */
    final protected static function createFromData(array $data)
    {
        $reflection = new \ReflectionClass(get_called_class());

        $transaction = $reflection->newInstanceWithoutConstructor();

        foreach ($data as $key => $value) {
            if ($reflection->hasProperty($key) && $reflection->getProperty($key)->isPublic()) {
                $transaction->{$key} = $value;
            }
        }

        return $transaction;
    }
}
