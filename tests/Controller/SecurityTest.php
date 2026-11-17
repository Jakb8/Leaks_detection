<?php

namespace App\Tests\Controller;

use App\Entity\User;
use App\Repository\UserRepository;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class SecurityTest extends WebTestCase
{
    public function testLoginPageAndProtectedRedirects(): void
    {
        $client = static::createClient();

        $client->request('GET', '/login');
        self::assertResponseIsSuccessful();

        $client->request('GET', '/');
        self::assertResponseRedirects('/login');

        $client->request('GET', '/api/feed');
        self::assertResponseRedirects('/login');
    }

    public function testSecurityHeadersAreSent(): void
    {
        $client = static::createClient();
        $client->request('GET', '/login');

        self::assertResponseIsSuccessful();
        self::assertResponseHeaderSame('X-Content-Type-Options', 'nosniff');
        self::assertResponseHeaderSame('X-Frame-Options', 'DENY');
        self::assertResponseHeaderSame('Referrer-Policy', 'strict-origin-when-cross-origin');
    }

    public function testIngestEndpointsRequireApiKey(): void
    {
        $client = static::createClient();

        $client->request('POST', '/api/ingest/leak', [], [], ['CONTENT_TYPE' => 'application/json'], '{}');
        self::assertResponseStatusCodeSame(401);

        $client->request('POST', '/api/ingest/attack', [], [], ['CONTENT_TYPE' => 'application/json'], '{}');
        self::assertResponseStatusCodeSame(401);
    }

    public function testIngestRejectsQueryStringApiKey(): void
    {
        $client = static::createClient();
        $client->request('POST', '/api/ingest/leak?apiKey=anything', [], [], ['CONTENT_TYPE' => 'application/json'], '{}');

        self::assertResponseStatusCodeSame(401);
    }

    public function testAdminCanBrowseAllPages(): void
    {
        $client = static::createClient();
        $admin = $this->findUser('admin@watchleaks.local');
        $client->loginUser($admin);

        foreach (['/', '/leaks', '/attacks', '/domains', '/domains/new', '/settings', '/audit', '/admin/users', '/help', '/api/feed'] as $uri) {
            $client->request('GET', $uri);
            self::assertResponseIsSuccessful($uri.' should be accessible to admin');
        }
    }

    public function testClientCannotAccessAdminPages(): void
    {
        $client = static::createClient();
        $clientUser = $this->findUser('client@watchleaks.local');
        $client->loginUser($clientUser);

        $client->request('GET', '/settings');
        self::assertResponseStatusCodeSame(403);

        $client->request('GET', '/admin/users');
        self::assertResponseStatusCodeSame(403);

        $client->request('GET', '/audit');
        self::assertResponseStatusCodeSame(403);

        $client->request('GET', '/');
        self::assertResponseIsSuccessful();
    }

    private function findUser(string $email): User
    {
        $user = static::getContainer()->get(UserRepository::class)->findOneBy(['email' => $email]);
        self::assertInstanceOf(User::class, $user, sprintf('Fixture user "%s" is missing (run composer test).', $email));

        return $user;
    }
}
