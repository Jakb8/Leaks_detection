<?php

namespace App\Tests\Controller;

use App\Entity\User;
use App\Repository\UserRepository;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class AuditTest extends WebTestCase
{
    public function testGeneratesDorksForDomain(): void
    {
        $client = static::createClient();
        $client->loginUser($this->findAdmin());

        $client->request('GET', '/audit?domain=example.com');
        self::assertResponseIsSuccessful();

        $html = $client->getResponse()->getContent();
        self::assertIsString($html);
        self::assertStringContainsString('site:t.me', $html);
        self::assertStringContainsString('example.com', $html);
        self::assertStringContainsString('google.com/search', $html);
        self::assertStringContainsString('domain:example.com', $html);
    }

    public function testInvalidDomainShowsError(): void
    {
        $client = static::createClient();
        $client->loginUser($this->findAdmin());

        $client->request('GET', '/audit?domain=not+a+domain');
        self::assertResponseIsSuccessful();
        self::assertStringContainsString('Invalid domain', (string) $client->getResponse()->getContent());
    }

    private function findAdmin(): User
    {
        $user = static::getContainer()->get(UserRepository::class)->findOneBy(['email' => 'admin@watchleaks.local']);
        self::assertInstanceOf(User::class, $user, 'Fixture admin user is missing (run composer test).');

        return $user;
    }
}
