<?php

namespace App\Tests\Repository;

use App\Entity\Attack;
use App\Entity\DataLeak;
use App\Entity\Domain;
use App\Enum\AttackStatus;
use App\Enum\AttackType;
use App\Enum\LeakType;
use App\Enum\Severity;
use App\Repository\AttackRepository;
use App\Repository\DataLeakRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

class FilterTest extends KernelTestCase
{
    private EntityManagerInterface $em;

    protected function setUp(): void
    {
        self::bootKernel();
        $this->em = static::getContainer()->get('doctrine')->getManager();
        $this->em->getConnection()->beginTransaction();

        $domain = new Domain();
        $domain->setName('test-search.example')
            ->setApiKey(bin2hex(random_bytes(16)))
            ->setMonitoringEnabled(true);
        $this->em->persist($domain);

        $attack = new Attack();
        $attack->setDomain($domain)
            ->setType(AttackType::A03_INJECTION)
            ->setSeverity(Severity::HIGH)
            ->setStatus(AttackStatus::DETECTED)
            ->setSourceIp('203.0.113.10')
            ->setEndpoint('/search-unique-token')
            ->setPayload('unique-token-payload')
            ->setDetectedAt(new \DateTimeImmutable('-1 minute'));
        $this->em->persist($attack);

        foreach (['a', 'b', 'c'] as $suffix) {
            $leak = new DataLeak();
            $leak->setDomain($domain)
                ->setType(LeakType::EMAIL)
                ->setSeverity(Severity::CRITICAL)
                ->setDataSample('unique-token sample '.$suffix)
                ->setEmail('unique-token@example.com')
                ->setIpAddress('198.51.100.4')
                ->setDetectedAt(new \DateTimeImmutable($suffix === 'a' ? '-1 minute' : '-2 minutes'));
            $this->em->persist($leak);
        }

        $this->em->flush();
    }

    protected function tearDown(): void
    {
        if (isset($this->em) && $this->em->getConnection()->isTransactionActive()) {
            $this->em->getConnection()->rollBack();
        }
        parent::tearDown();
    }

    public function testSearchFindsAttacksAndLeaks(): void
    {
        $attacks = static::getContainer()->get(AttackRepository::class)->findFiltered(null, null, null, null, 'unique-token');
        self::assertCount(1, $attacks);

        $leaks = static::getContainer()->get(DataLeakRepository::class)->findFiltered(null, null, null, false, 'unique-token');
        self::assertCount(3, $leaks);

        $none = static::getContainer()->get(DataLeakRepository::class)->findFiltered(null, null, null, false, 'no-such-token');
        self::assertSame([], $none);
    }

    public function testEmptyDomainFilterReturnsNothing(): void
    {
        $attacks = static::getContainer()->get(AttackRepository::class)->findFiltered([], null, null, null);
        self::assertSame([], $attacks);

        $leaks = static::getContainer()->get(DataLeakRepository::class)->findFiltered([], null, null);
        self::assertSame([], $leaks);
    }

    public function testRecentLeaksHonoursLimit(): void
    {
        $leaks = static::getContainer()->get(DataLeakRepository::class)->findRecentLeaks(null, 2);
        self::assertCount(2, $leaks);
    }

    public function testRecentLeaksHonoursSince(): void
    {
        $since = new \DateTimeImmutable('-90 seconds');
        $leaks = static::getContainer()->get(DataLeakRepository::class)->findRecentLeaks(null, 20, $since);
        self::assertCount(1, $leaks);
    }
}
