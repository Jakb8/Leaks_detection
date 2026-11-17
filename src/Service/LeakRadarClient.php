<?php

namespace App\Service;

use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Client for the LeakRadar.io credential-exposure API.
 *
 * Aggregate domain/combolist reports are public (no key). Listing the actual
 * url/user/password records requires a paid API key.
 *
 * @see https://docs.leakradar.io
 */
class LeakRadarClient
{
    private const BASE_URL = 'https://api.leakradar.io';
    private const USER_AGENT = 'WatchLeaks/1.0 (+https://watchleaks.local)';

    /** Microseconds to wait between requests. */
    private int $throttleUs = 700000;

    public function __construct(
        private readonly HttpClientInterface $httpClient,
        private readonly SettingsService $settings,
    ) {
    }

    public function hasApiKey(): bool
    {
        return trim((string) ($this->settings->get(SettingsService::LEAKRADAR_API_KEY) ?? '')) !== '';
    }

    /**
     * Public stealer-log exposure report for a domain (no API key).
     *
     * @return array<string, mixed>
     */
    public function report(string $domain): array
    {
        return $this->request('/search/domain/'.rawurlencode($domain)) ?? [];
    }

    /**
     * Public combolist exposure report for a domain (no API key).
     *
     * @return array<string, mixed>
     */
    public function combolistReport(string $domain): array
    {
        return $this->request('/search/combolist/domain/'.rawurlencode($domain).'/report') ?? [];
    }

    /**
     * Actual leak records for a domain (requires API key).
     *
     * @return array{items: array<int, array<string, mixed>>, total: int, unlocked: int}|null
     */
    public function allLeaks(string $domain, int $page = 1, int $pageSize = 20, bool $autoUnlock = false): ?array
    {
        if (!$this->hasApiKey()) {
            return null;
        }

        $query = http_build_query([
            'page' => $page,
            'page_size' => $pageSize,
            'auto_unlock' => $autoUnlock ? 'true' : 'false',
        ]);

        $data = $this->request('/search/domain/'.rawurlencode($domain).'/all?'.$query);
        if (!is_array($data) || !isset($data['items']) || !is_array($data['items'])) {
            return null;
        }

        return [
            'items' => $data['items'],
            'total' => (int) ($data['total'] ?? 0),
            'unlocked' => (int) ($data['total_unlocked'] ?? 0),
        ];
    }

    /**
     * Actual combolist credentials for a domain (requires API key).
     *
     * @return array{items: array<int, array<string, mixed>>, total: int, unlocked: int}|null
     */
    public function combolistLeaks(string $domain, int $page = 1, int $pageSize = 20): ?array
    {
        if (!$this->hasApiKey()) {
            return null;
        }

        $query = http_build_query(['page' => $page, 'page_size' => $pageSize]);
        $data = $this->request('/search/combolist/domain/'.rawurlencode($domain).'?'.$query);
        if (!is_array($data) || !isset($data['items']) || !is_array($data['items'])) {
            return null;
        }

        return [
            'items' => $data['items'],
            'total' => (int) ($data['total'] ?? 0),
            'unlocked' => (int) ($data['total_unlocked'] ?? 0),
        ];
    }

    private function request(string $path): ?array
    {
        usleep($this->throttleUs);

        $headers = ['Accept' => 'application/json', 'User-Agent' => self::USER_AGENT];
        $apiKey = trim((string) ($this->settings->get(SettingsService::LEAKRADAR_API_KEY) ?? ''));
        if ($apiKey !== '') {
            $headers['Authorization'] = 'Bearer '.$apiKey;
        }

        try {
            $response = $this->httpClient->request('GET', self::BASE_URL.$path, [
                'headers' => $headers,
                'timeout' => 25,
            ]);

            $status = $response->getStatusCode();
            $body = $response->getContent(false);

            if ($status === 429) {
                return null;
            }
            if ($status >= 400) {
                return null;
            }

            $decoded = json_decode($body, true);
            return is_array($decoded) ? $decoded : null;
        } catch (TransportExceptionInterface) {
            return null;
        }
    }
}
