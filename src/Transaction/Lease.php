<?php

declare(strict_types=1);

namespace LTO\Transaction;

use LTO\Transaction;
use function LTO\decode;
use function LTO\is_valid_address;

/**
 * LTO transaction to start leasing.
 */
class Lease extends Transaction
{
    /** Minimum transaction fee */
    public const MINIMUM_FEE = 100000000;

    /** Transaction type */
    public const TYPE = 8;

    /** Transaction version */
    public const VERSION  = 2;

    /** @var int */
    public $amount;

    /** @var string */
    public $recipient;


    /**
     * Class constructor.
     *
     * @param string $recipient   Recipient address (base58 encoded)
     * @param int    $amount      Amount of LTO (*10^8)
     */
    public function __construct(string $recipient, int $amount)
    {
        if ($amount <= 0) {
            throw new \InvalidArgumentException("Invalid amount; should be greater than 0");
        }

        if (!is_valid_address($recipient, 'base58')) {
            throw new \InvalidArgumentException("Invalid recipient address; is it base58 encoded?");
        }

        $this->amount = $amount;
        $this->recipient = $recipient;
        $this->fee = self::MINIMUM_FEE;
    }

    /**
     * Prepare signing the transaction.
     */
    public function toBinary(): string
    {
        if ($this->senderPublicKey === null) {
            throw new \BadMethodCallException("Sender public key not set");
        }

        if ($this->timestamp === null) {
            throw new \BadMethodCallException("Timestamp not set");
        }

        return pack(
            'CCCa32a26JJJ',
            static::TYPE,
            static::VERSION,
            0,
            decode($this->senderPublicKey, 'base58'),
            decode($this->recipient, 'base58'),
            $this->amount,
            $this->fee,
            $this->timestamp
        );
    }

    /**
     * Create a Cancel Lease transaction for this lease.
     */
    public function cancel(): CancelLease
    {
        return new CancelLease($this->getId());
    }

    /**
     * @inheritDoc
     */
    public function jsonSerialize(): array
    {
        return
            ['type' => static::TYPE, 'version' => static::VERSION] +
            parent::jsonSerialize();
    }

    /**
     * @inheritDoc
     */
    public static function fromData(array $data)
    {
        static::assertNoMissingKeys($data);
        static::assertTypeAndVersion($data, static::TYPE, static::VERSION);

        return static::createFromData($data);
    }
}
