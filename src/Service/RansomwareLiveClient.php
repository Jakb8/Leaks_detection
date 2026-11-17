<?php

namespace App\Service;

use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Client for ransomware.live — a free, real-time feed of ransomware victims
 * published on dark-web leak sites.
 *
 * @see https://api.ransomware.live
 */
class RansomwareLiveClient
{
    private const BASE_URL = 'https://api.ransomware.live';
    private const USER_AGENT = 'WatchLeaks/1.0 (+https://watchleaks.local)';

    /** Microseconds to wait between requests to be gentle on the free API. */
    private int $throttleUs = 1000000;

    public function __construct(
        private readonly HttpClientInterface $httpClient,
    ) {
    }

    /**
     * Search the ransomware victim database by keyword (company/domain name).
     *
     * @return array<int, array<string, mixed>>
     */
    public function searchVictims(string $keyword): array
    {
        $keyword = trim($keyword);
        if ($keyword === '') {
            return [];
        }

        $url = self::BASE_URL.'/v2/searchvictims/'.rawurlencode($keyword);

        usleep($this->throttleUs);

        try {
            $response = $this->httpClient->request('GET', $url, [
                'headers' => ['Accept' => 'application/json', 'User-Agent' => self::USER_AGENT],
                'timeout' => 25,
            ]);

            $status = $response->getStatusCode();
            if ($status === 429 || $status === 404 || $status >= 400) {
                return [];
            }

            $data = json_decode($response->getContent(false), true);
        } catch (TransportExceptionInterface) {
            return [];
        }

        if (!is_array($data)) {
            return [];
        }

        if (isset($data['victims']) && is_array($data['victims'])) {
            return $data['victims'];
        }

        return array_is_list($data) ? $data : [];
    }
}
