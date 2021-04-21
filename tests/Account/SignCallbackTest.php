<?php

namespace LTO\Tests\Account;

use LTO\Account;
use LTO\Account\SignCallback;
use LTO\Cryptography;
use PHPUnit\Framework\TestCase;

/**
 * @covers \LTO\Account\SignCallback
 */
class SignCallbackTest extends TestCase
{
    public function hashAlgoProvider()
    {
        return [
            [null],
            ['sha256'],
            ['md5'],
            ['sha3-512'],
        ];
    }

    /**
     * @dataProvider hashAlgoProvider
     */
    public function test(?string $hashAlgo)
    {
        $message = $hashAlgo === null ? 'hello' : hash($hashAlgo, 'hello', true);

        $account = $this->createMock(Account::class);
        $account->sign = (object)[
            'secretkey' => base58_decode('4zsR9xoFpxfnNwLcY4hdRUarwf5xWtLj6FpKGDFBgscPxecPj2qgRNx4kJsFCpe9YDxBRNoeBWTh2SDAdwTySomS'),
            'publickey' => base58_decode('GjSacB6a5DFNEHjDSmn724QsrRStKYzkahPH67wyrhAY')
        ];
        $account->expects($this->any())->method('getPublicSignKey')
            ->willReturn('GjSacB6a5DFNEHjDSmn724QsrRStKYzkahPH67wyrhAY');
        $account->expects($this->once())->method('sign')
            ->with($message)
            ->willReturn('__mock_signature__'); // Would normally return the signature

        $algo = 'ed25519' . ($hashAlgo !== null ? '-' . $hashAlgo : '');

        $sign = new SignCallback($account);
        $ret = $sign('hello', 'GjSacB6a5DFNEHjDSmn724QsrRStKYzkahPH67wyrhAY', $algo);

        $this->assertSame('__mock_signature__', $ret);
    }

    public function testInvalidAccount()
    {
        $account = new Account($this->createMock(Cryptography::class));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Unable to use account to sign; no secret sign key');

        new SignCallback($account);
    }

    public function testKeyMismatch()
    {
        $account = $this->createMock(Account::class);
        $account->sign = (object)[
            'secretkey' => base58_decode('4zsR9xoFpxfnNwLcY4hdRUarwf5xWtLj6FpKGDFBgscPxecPj2qgRNx4kJsFCpe9YDxBRNoeBWTh2SDAdwTySomS'),
            'publickey' => base58_decode('GjSacB6a5DFNEHjDSmn724QsrRStKYzkahPH67wyrhAY')
        ];

        $sign = new SignCallback($account);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('keyId doesn\'t match account public key');

        $sign('hello', '4q7HKMbwbLcG58iFV3pz4vkRnPTwbrY9Q5JrwnwLEZCC', 'ed25519');
    }

    public function invalidAlgorithmProvider()
    {
        return [
            ['hmac'],
            ['hmac-sha256'],
            ['ed25519-kaccak'],
        ];
    }

    /**
     * @dataProvider invalidAlgorithmProvider
     */
    public function testInvalidAlgorithm(string $algo)
    {
        $account = $this->createMock(Account::class);
        $account->sign = (object)[
            'secretkey' => base58_decode('4zsR9xoFpxfnNwLcY4hdRUarwf5xWtLj6FpKGDFBgscPxecPj2qgRNx4kJsFCpe9YDxBRNoeBWTh2SDAdwTySomS'),
            'publickey' => base58_decode('GjSacB6a5DFNEHjDSmn724QsrRStKYzkahPH67wyrhAY')
        ];
        $account->expects($this->any())->method('getPublicSignKey')
            ->willReturn('GjSacB6a5DFNEHjDSmn724QsrRStKYzkahPH67wyrhAY');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported algorithm: ' . $algo);

        $sign = new SignCallback($account);
        $sign('hello', 'GjSacB6a5DFNEHjDSmn724QsrRStKYzkahPH67wyrhAY', $algo);
    }
}
