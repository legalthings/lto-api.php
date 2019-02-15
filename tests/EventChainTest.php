<?php

namespace LTO;

use PHPUnit\Framework\TestCase;
use LTO\Account;
use LTO\EventChain;

/**
 * @covers \LTO\EventChain
 */
class EventChainTest extends TestCase
{
    use \Jasny\TestHelper;
    
    public function testConstruct()
    {
        $chain = new EventChain();
        
        $this->assertNull($chain->getLatestHash());
    }
    
    public function testConstructId()
    {
        $chain = new EventChain('L1hGimV7Pp2CFNUnTCitqWDbk9Zng3r3uc66dAG6hLwEx');
        
        $this->assertAttributeEquals('L1hGimV7Pp2CFNUnTCitqWDbk9Zng3r3uc66dAG6hLwEx', 'id', $chain);
        $this->assertEquals('9HM1ykH7AxLgdCqBBeUhvoTH4jkq3zsZe4JGTrjXVENg', $chain->getLatestHash());
    }
    
    public function testConstructLatestHash()
    {
        $chain = new EventChain('L1hGimV7Pp2CFNUnTCitqWDbk9Zng3r3uc66dAG6hLwEx', '3yMApqCuCjXDWPrbjfR5mjCPTHqFG8Pux1TxQrEM35jj');
        
        $this->assertAttributeEquals('L1hGimV7Pp2CFNUnTCitqWDbk9Zng3r3uc66dAG6hLwEx', 'id', $chain);
        $this->assertEquals('3yMApqCuCjXDWPrbjfR5mjCPTHqFG8Pux1TxQrEM35jj', $chain->getLatestHash());
    }
    
    public function testAdd()
    {
        $event = $this->createMock(Event::class);
        $event->method('getHash')->willReturn("J26EAStUDXdRUMhm1UcYXUKtJWTkcZsFpxHRzhkStzbS");
        
        $chain = new EventChain('L1hGimV7Pp2CFNUnTCitqWDbk9Zng3r3uc66dAG6hLwEx', '3yMApqCuCjXDWPrbjfR5mjCPTHqFG8Pux1TxQrEM35jj');
        
        $chain->add($event);
        $this->assertEquals('J26EAStUDXdRUMhm1UcYXUKtJWTkcZsFpxHRzhkStzbS', $chain->getLatestHash());
    }
    
    
    public function testGetRandomNonce()
    {
        $chain = new EventChain();
        
        $nonce = $this->callPrivateMethod($chain, 'getRandomNonce');
        $this->assertEquals(20, strlen($nonce));
    }
    
    public function testInitForSeedNonce()
    {
        $account = $this->createMock(Account::class);
        $account->sign = (object)['publickey' => base58_decode("8MeRTc26xZqPmQ3Q29RJBwtgtXDPwR7P9QNArymjPLVQ")];
        
        $chain = $this->createPartialMock(EventChain::class, ['getRandomNonce']);
        $chain->expects($this->never())->method('getRandomNonce');
        
        $chain->initFor($account, 'foo');
        
        $this->assertAttributeEquals('2b6QYLttL2R3CLGL4fUB9vaXXX4c5HJanjV5QecmAYLCrD52o6is1fRMGShUUF', 'id', $chain);
        $this->assertEquals('8FjrD9Req4C61RcawRC5HaTUvuetU2BwABTiQBVheU2R', $chain->getLatestHash());
    }
    
    public function testInitFor()
    {
        $account = $this->createMock(Account::class);
        $account->sign = (object)['publickey' => base58_decode("8MeRTc26xZqPmQ3Q29RJBwtgtXDPwR7P9QNArymjPLVQ")];
        
        $chain = $this->createPartialMock(EventChain::class, ['getRandomNonce']);
        $chain->expects($this->once())->method('getRandomNonce')->willReturn(str_repeat("\0", 20));
        
        $chain->initFor($account);
        
        $this->assertAttributeEquals('2ar3wSjTm1fA33qgckZ5Kxn1x89gKKGi6TJsZjRoqb7sjUE8GZXjLaYCbCa2GX', 'id', $chain);
        $this->assertEquals('3NTzfLcXq1D5BRzhj9EyVbmAcLsz1pa6ZjdxRySbYze1', $chain->getLatestHash());
    }
    
    /**
     * @expectedException \BadMethodCallException
     */
    public function testInitForExisting()
    {
        $account = $this->createMock(Account::class);
        
        $chain = $this->createPartialMock(EventChain::class, ['getNonce']);
        $chain->id = '123';
        
        $chain->initFor($account);
    }
    
    /**
     * @expectedException \InvalidArgumentException
     */
    public function testInitForInvalidAccount()
    {
        $account = $this->createMock(Account::class);
        
        $chain = $this->createPartialMock(EventChain::class, ['getNonce']);
        
        $chain->initFor($account);
    }
}
