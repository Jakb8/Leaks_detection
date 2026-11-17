<?php

namespace App\Tests\Controller;

use App\Entity\User;
use App\Repository\UserRepository;
use App\Service\SettingsService;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class SettingsTest extends WebTestCase
{
    public function testAdminCanSaveKeepAndClearApiKeys(): void
    {
        $client = static::createClient();
        $client->loginUser($this->findAdmin());

        $crawler = $client->request('GET', '/settings');
        self::assertResponseIsSuccessful();
        self::assertSelectorExists('input[name="xon_api_key"]');
        self::assertSelectorExists('input[name="leakradar_api_key"]');

        $token = $this->apiKeysToken($crawler);

        $client->request('POST', '/settings', [
            '_token' => $token,
            'api_keys_save' => '1',
            'xon_api_key' => 'test-xon-key',
            'leakradar_api_key' => 'test-leakradar-key',
        ]);
        self::assertResponseRedirects('/settings');

        self::assertSame('test-xon-key', $this->settings()->get(SettingsService::XON_API_KEY));
        self::assertSame('test-leakradar-key', $this->settings()->get(SettingsService::LEAKRADAR_API_KEY));

        $client->request('POST', '/settings', [
            '_token' => $token,
            'api_keys_save' => '1',
            'xon_api_key' => '',
            'leakradar_api_key' => '',
        ]);
        self::assertResponseRedirects('/settings');
        self::assertSame('test-xon-key', $this->settings()->get(SettingsService::XON_API_KEY));
        self::assertSame('test-leakradar-key', $this->settings()->get(SettingsService::LEAKRADAR_API_KEY));

        $client->request('POST', '/settings', [
            '_token' => $token,
            'api_keys_save' => '1',
            'xon_api_key_clear' => '1',
            'leakradar_api_key_clear' => '1',
        ]);
        self::assertResponseRedirects('/settings');
        self::assertFalse($this->settings()->has(SettingsService::XON_API_KEY));
        self::assertFalse($this->settings()->has(SettingsService::LEAKRADAR_API_KEY));
    }

    public function testInvalidCsrfDoesNotChangeApiKeys(): void
    {
        $client = static::createClient();
        $client->loginUser($this->findAdmin());

        $crawler = $client->request('GET', '/settings');
        $token = $this->apiKeysToken($crawler);

        $client->request('POST', '/settings', [
            '_token' => $token,
            'api_keys_save' => '1',
            'xon_api_key' => 'known-key',
        ]);

        $client->request('POST', '/settings', [
            '_token' => 'invalid',
            'api_keys_save' => '1',
            'xon_api_key' => 'replacement-key',
        ]);
        self::assertResponseRedirects('/settings');
        self::assertSame('known-key', $this->settings()->get(SettingsService::XON_API_KEY));

        $client->request('POST', '/settings', [
            '_token' => $token,
            'api_keys_save' => '1',
            'xon_api_key_clear' => '1',
        ]);
    }

    private function settings(): SettingsService
    {
        return static::getContainer()->get(SettingsService::class);
    }

    private function findAdmin(): User
    {
        $user = static::getContainer()->get(UserRepository::class)->findOneBy(['email' => 'admin@watchleaks.local']);
        self::assertInstanceOf(User::class, $user, 'Fixture admin user is missing (run composer test).');

        return $user;
    }

    private function apiKeysToken(\Symfony\Component\DomCrawler\Crawler $crawler): string
    {
        $token = $crawler->filterXPath('//form[.//*[@name="api_keys_save"]]//input[@name="_token"]')->attr('value');
        self::assertNotNull($token);

        return $token;
    }
}
