<?php

declare(strict_types=1);

namespace LTO\Tests\Transaction;

use LTO\AccountFactory;
use LTO\PublicNode;
use LTO\Transaction;
use LTO\Transaction\RevokeAssociation;
use PHPUnit\Framework\TestCase;
use function LTO\decode;
use function LTO\encode;

/**
 * @covers \LTO\Transaction
 * @covers \LTO\Transaction\RevokeAssociation
 * @covers \LTO\Transaction\Pack\AssociationV1
 */
class RevokeAssociationTest extends TestCase
{
    protected const ACCOUNT_SEED = "df3dd6d884714288a39af0bd973a1771c9f00f168cf040d6abb6a50dd5e055d8";

    /** @var \LTO\Account */
    protected $account;

    public function setUp(): void
    {
        $this->account = (new AccountFactory('T'))->seed(self::ACCOUNT_SEED);
    }

    public function testConstruct()
    {
        $transaction = new RevokeAssociation('3N3Cn2pYtqzj7N9pviSesNe8KG9Cmb718Y1', 42);

        $this->assertEquals(100000000, $transaction->fee);
        $this->assertEquals('3N3Cn2pYtqzj7N9pviSesNe8KG9Cmb718Y1', $transaction->party);
        $this->assertEquals(42, $transaction->associationType);
    }

    public function encodedHashProvider()
    {
        return [
            'raw' => [hash('sha256', 'foo', true), 'raw'],
            'hex' => [hash('sha256', 'foo'), 'hex'],
            'base58' => [encode(hash('sha256', 'foo', true), 'base58'), 'base58'],
            'base64' => [encode(hash('sha256', 'foo', true), 'base64'), 'base64'],
        ];
    }

    /**
     * @dataProvider encodedHashProvider
     */
    public function testConstructWithHash(string $hash, string $encoding)
    {
        $transaction = new RevokeAssociation('3N3Cn2pYtqzj7N9pviSesNe8KG9Cmb718Y1', 42, $hash, $encoding);

        $this->assertEquals(100000000, $transaction->fee);
        $this->assertEquals('3N3Cn2pYtqzj7N9pviSesNe8KG9Cmb718Y1', $transaction->party);
        $this->assertEquals(42, $transaction->associationType);
        $this->assertEquals(
            base58_encode(hash('sha256', 'foo', true)),
            $transaction->hash
        );
    }

    public function invalidPartyProvider()
    {
        return [
            'test' => ['test'],
            'hello' => ['hello'],
            'raw' => [decode('3N3Cn2pYtqzj7N9pviSesNe8KG9Cmb718Y1', 'base58')],
        ];
    }

    /**
     * @dataProvider invalidPartyProvider
     */
    public function testConstructInvalidparty($party)
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("Invalid party address; is it base58 encoded?");

        new RevokeAssociation($party, 42);
    }

    public function testToBinaryNoSender()
    {
        $transaction = new RevokeAssociation('3N3Cn2pYtqzj7N9pviSesNe8KG9Cmb718Y1', 42);
        $transaction->timestamp = (new \DateTime('2018-03-01T00:00:00+00:00'))->getTimestamp();

        $this->expectException(\BadMethodCallException::class);
        $this->expectExceptionMessage("Sender public key not set");

        $transaction->toBinary();
    }

    public function testToBinaryNoTimestamp()
    {
        $transaction = new RevokeAssociation('3N3Cn2pYtqzj7N9pviSesNe8KG9Cmb718Y1', 42);
        $transaction->senderPublicKey = '4EcSxUkMxqxBEBUBL2oKz3ARVsbyRJTivWpNrYQGdguz';

        $this->expectException(\BadMethodCallException::class);
        $this->expectExceptionMessage("Timestamp not set");

        $transaction->toBinary();
    }

    public function testToBinaryWithUnsupportedVersion()
    {
        $transaction = new RevokeAssociation('3N3Cn2pYtqzj7N9pviSesNe8KG9Cmb718Y1', 42);
        $transaction->version = 99;

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage("Unsupported revoke association tx version 99");

        $transaction->toBinary();
    }


    public function hashProvider()
    {
        return [
            'with hash' => [
                hash('sha256', 'foo'),
                '66XHTtBAa3XDmhThKb43zRUBBAEk73B9Bcs1Dx4UwhQUjnaSUUhVVKsYzN1hfZaURALDq1tV83WUW6GbTAyM7zjQ',
            ],
            'without hash' => [
                '',
                '3MHD8faY9rNpYh58KdLZxdp9Btby3SkzmtCv7R4sM1EvccKvRD4rKXua5h4ENsCkrkfNkApNF7UqxR5M2C3GXXWZ',
            ],
        ];
    }

    /**
     * @dataProvider hashProvider
     */
    public function testSign(string $hash, string $signature)
    {
        $transaction = new RevokeAssociation('3N3Cn2pYtqzj7N9pviSesNe8KG9Cmb718Y1', 42, $hash);
        $transaction->timestamp = (new \DateTime('2018-03-01T00:00:00+00:00'))->getTimestamp();

        $this->assertFalse($transaction->isSigned());

        $ret = $transaction->signWith($this->account);
        $this->assertSame($transaction, $ret);

        $this->assertTrue($transaction->isSigned());

        $this->assertEquals($hash === '' ? 82 : 116, strlen($transaction->toBinary()));

        $this->assertEquals('3MtHYnCkd3oFZr21yb2vEdngcSGXvuNNCq2', $transaction->sender);
        $this->assertEquals('4EcSxUkMxqxBEBUBL2oKz3ARVsbyRJTivWpNrYQGdguz', $transaction->senderPublicKey);
        $this->assertEquals($signature, $transaction->proofs[0]);

        // Unchanged
        $this->assertEquals((new \DateTime('2018-03-01T00:00:00+00:00'))->getTimestamp(), $transaction->timestamp);

        $this->assertTrue($this->account->verify($transaction->proofs[0], $transaction->toBinary()));
    }

    public function dataProvider()
    {
        $data = [
            "type" => 17,
            "version" => 1,
            "party" => "3N9ChkxWXqgdWLLErWFrSwjqARB6NtYsvZh",
            "associationType" => 42,
            "hash" => "3yMApqCuCjXDWPrbjfR5mjCPTHqFG8Pux1TxQrEM35jj",
            "sender" => "3NBcx7AQqDopBj3WfwCVARNYuZyt1L9xEVM",
            "senderPublicKey" => "7gghhSwKRvshZwwh6sG97mzo1qoFtHEQK7iM4vGcnEt7",
            "timestamp" => 1610154732000,
            "fee" => 100000000,
            "proofs" => [
                "4NrsjbkkWyH4K57jf9MQ5Ya9ccvXtCg2BQV2LsHMMacZZojbcRgesB1MruVQtCaZdvFSswwju5zCxisG3ZaQ2LKF"
            ],
        ];

        return [
            'new' => [$data, null, null],
            'unconfirmed' => [$data, 'UMkS6oU6GfhhZngST6opVQYvCbLMnWVL4q6SC46F7ch', null],
            'confirmed' => [$data, 'UMkS6oU6GfhhZngST6opVQYvCbLMnWVL4q6SC46F7ch', 1221474],
        ];
    }

    /**
     * @dataProvider dataProvider
     */
    public function testFromData(array $data, ?string $id, ?int $height)
    {
        if ($id !== null) $data += ['id' => $id];
        if ($height !== null) $data += ['height' => $height];

        /** @var RevokeAssociation $transaction */
        $transaction = Transaction::fromData($data);

        $this->assertInstanceOf(RevokeAssociation::class, $transaction);

        $this->assertEquals($id, $transaction->id);
        $this->assertEquals('3NBcx7AQqDopBj3WfwCVARNYuZyt1L9xEVM', $transaction->sender);
        $this->assertEquals('7gghhSwKRvshZwwh6sG97mzo1qoFtHEQK7iM4vGcnEt7', $transaction->senderPublicKey);
        $this->assertEquals(100000000, $transaction->fee);
        $this->assertEquals(1610154732000, $transaction->timestamp);
        $this->assertEquals('3N9ChkxWXqgdWLLErWFrSwjqARB6NtYsvZh', $transaction->party);
        $this->assertEquals(
            ['4NrsjbkkWyH4K57jf9MQ5Ya9ccvXtCg2BQV2LsHMMacZZojbcRgesB1MruVQtCaZdvFSswwju5zCxisG3ZaQ2LKF'],
            $transaction->proofs
        );
        $this->assertEquals($height, $transaction->height);
    }

    public function testFromDataWithMissingKeys()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("Invalid data, missing keys: party, associationType, version, sender, senderPublicKey, timestamp, fee, proofs");

        Transaction::fromData(['type' => RevokeAssociation::TYPE]);
    }

    public function testFromDataWithIncorrectType()
    {
        $data = $this->dataProvider()['confirmed'][0];
        $data['type'] = 99;

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("Invalid type 99, should be 17");

        RevokeAssociation::fromData($data);
    }

    /**
     * @dataProvider dataProvider
     */
    public function testJsonSerialize(array $data, ?string $id, ?int $height)
    {
        if ($id !== null) $data += ['id' => $id];
        if ($height !== null) $data += ['height' => $height];

        $transaction = new RevokeAssociation('3N9ChkxWXqgdWLLErWFrSwjqARB6NtYsvZh', 46, hash('sha256', 'foo'));
        $transaction->id = $id;
        $transaction->sender = '3NBcx7AQqDopBj3WfwCVARNYuZyt1L9xEVM';
        $transaction->senderPublicKey = '7gghhSwKRvshZwwh6sG97mzo1qoFtHEQK7iM4vGcnEt7';
        $transaction->fee = 100000000;
        $transaction->timestamp = 1610154732000;
        $transaction->party = '3N9ChkxWXqgdWLLErWFrSwjqARB6NtYsvZh';
        $transaction->associationType = 42;
        $transaction->hash = encode(hash('sha256', 'foo', true), 'base58');
        $transaction->proofs[] = '4NrsjbkkWyH4K57jf9MQ5Ya9ccvXtCg2BQV2LsHMMacZZojbcRgesB1MruVQtCaZdvFSswwju5zCxisG3ZaQ2LKF';
        $transaction->height = $height;

        $this->assertEquals($data, $transaction->jsonSerialize());
    }

    public function testBroadcast()
    {
        $transaction = new RevokeAssociation('3N3Cn2pYtqzj7N9pviSesNe8KG9Cmb718Y1', 42);

        $broadcastedTransaction = clone $transaction;
        $broadcastedTransaction->id = 'UMkS6oU6GfhhZngST6opVQYvCbLMnWVL4q6SC46F7ch';

        $node = $this->createMock(PublicNode::class);
        $node->expects($this->once())->method('broadcast')
            ->with($this->identicalTo($transaction))
            ->willReturn($broadcastedTransaction);

        $ret = $transaction->broadcastTo($node);

        $this->assertSame($broadcastedTransaction, $ret);
    }


    /**
     * @dataProvider encodedHashProvider
     */
    public function testGetHash(string $hash, string $encoding)
    {
        $transaction = new RevokeAssociation('3N9ChkxWXqgdWLLErWFrSwjqARB6NtYsvZh', 46, hash('sha256', 'foo'));

        $this->assertEquals($hash, $transaction->getHash($encoding));
    }
}
