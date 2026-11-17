<?php

namespace App\Service;

use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Client for the Hudson Rock "Cavalier" OSINT API — a free, real-time source of
 * credentials harvested by information-stealer malware (RedLine, Raccoon, etc.)
 * and associated with a domain or email address.
 *
 * @see https://cavalier.hudsonrock.com
 */
class HudsonRockClient
{
    private const BASE_URL = 'https://cavalier.hudsonrock.com/api/json/v2/osint-tools';
    private const USER_AGENT = 'WatchLeaks/1.0 (+https://watchleaks.local)';

    /** Microseconds to wait between requests to respect the free API. */
    private int $throttleUs = 800000;

    public function __construct(
        private readonly HttpClientInterface $httpClient,
    ) {
    }

    /**
     * Infostealer infection data associated with a domain.
     *
     * @return array<string, mixed>
     */
    public function domain(string $domain): array
    {
        return $this->request(self::BASE_URL.'/search-by-domain?domain='.rawurlencode($domain));
    }

    /**
     * Infostealer infection data associated with an email address.
     *
     * @return array<string, mixed>
     */
    public function email(string $email): array
    {
        return $this->request(self::BASE_URL.'/search-by-email?email='.rawurlencode($email));
    }

    /**
     * Infostealer infection data associated with a username.
     *
     * @return array<string, mixed>
     */
    public function username(string $username): array
    {
        return $this->request(self::BASE_URL.'/search-by-username?username='.rawurlencode($username));
    }

    /**
     * @return array<string, mixed>
     */
    private function request(string $url): array
    {
        usleep($this->throttleUs);

        try {
            $response = $this->httpClient->request('GET', $url, [
                'headers' => ['Accept' => 'application/json', 'User-Agent' => self::USER_AGENT],
                'timeout' => 25,
            ]);

            $status = $response->getStatusCode();
            if ($status === 429 || $status >= 400) {
                return [];
            }

            $data = json_decode($response->getContent(false), true);
        } catch (TransportExceptionInterface) {
            return [];
        }

        return is_array($data) ? $data : [];
    }
}
