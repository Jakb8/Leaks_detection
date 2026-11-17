<?php

namespace App\Service;

use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Client for the XposedOrNot (XON) data breach API.
 *
 * @see https://xposedornot.com/api-docs
 */
class XposedOrNotClient
{
    private const BASE_URL = 'https://api.xposedornot.com';
    private const PASS_URL = 'https://passwords.xposedornot.com';
    private const USER_AGENT = 'WatchLeaks/1.0 (+https://watchleaks.local)';

    /** Microseconds to wait between requests to respect the 2 req/s free-tier limit. */
    private int $throttleUs = 600000;

    public function __construct(
        private readonly HttpClientInterface $httpClient,
    ) {
    }

    /**
     * All known breaches, optionally filtered by domain.
     *
     * @return array<int, array<string, mixed>>
     */
    public function breaches(?string $domain = null): array
    {
        $url = self::BASE_URL.'/v1/breaches';
        if ($domain !== null && $domain !== '') {
            $url .= '?domain='.rawurlencode($domain);
        }

        $data = $this->request($url);
        if (!is_array($data)) {
            return [];
        }

        $list = $data['exposedBreaches'] ?? $data['breaches'] ?? [];
        return is_array($list) ? $list : [];
    }

    /**
     * Breaches affecting a single domain.
     *
     * @return array<int, array<string, mixed>>
     */
    public function breachesByDomain(string $domain): array
    {
        return $this->breaches($domain);
    }

    /**
     * Breaches for a domain using the authenticated domain-breaches endpoint.
     *
     * @return array<int, array<string, mixed>>
     */
    public function domainBreaches(string $apiKey): array
    {
        try {
            $response = $this->httpClient->request('POST', self::BASE_URL.'/v1/domain-breaches/', [
                'headers' => [
                    'x-api-key' => $apiKey,
                    'Content-Length' => '0',
                    'Accept' => 'application/json',
                    'User-Agent' => self::USER_AGENT,
                ],
                'timeout' => 25,
            ]);

            if ($response->getStatusCode() >= 400) {
                return [];
            }

            $data = json_decode($response->getContent(false), true);
        } catch (TransportExceptionInterface) {
            return [];
        }

        if (!is_array($data) || !isset($data['metrics']['Breaches_Details']) || !is_array($data['metrics']['Breaches_Details'])) {
            return [];
        }

        $details = $data['metrics']['Detailed_Breach_Info'] ?? [];
        $details = is_array($details) ? $details : [];

        $out = [];
        foreach ($data['metrics']['Breaches_Details'] as $breach) {
            if (!is_array($breach)) {
                continue;
            }

            $name = (string) ($breach['breach'] ?? $breach['breachID'] ?? '');
            $extra = is_array($details[$name] ?? null) ? $details[$name] : [];

            $out[] = array_merge($extra, [
                'breachID' => $name,
                'domain' => (string) ($breach['domain'] ?? ''),
                'email' => (string) ($breach['email'] ?? ''),
                'breachedDate' => $extra['breached_date'] ?? null,
                'exposedData' => $extra['xposed_data'] ?? null,
                'exposedRecords' => $extra['xposed_records'] ?? 0,
                'exposureDescription' => $extra['xposure_desc'] ?? null,
                'passwordRisk' => $extra['password_risk'] ?? null,
            ]);
        }

        return $out;
    }

    /**
     * Check whether an email appears in known breaches.
     *
     * @return array{breached: bool, breaches: string[], raw: array<string, mixed>}
     */
    public function checkEmail(string $email): array
    {
        $data = $this->request(self::BASE_URL.'/v1/check-email/'.rawurlencode($email));

        if (!is_array($data) || !isset($data['breaches'])) {
            return ['breached' => false, 'breaches' => [], 'raw' => is_array($data) ? $data : []];
        }

        $breaches = $data['breaches'];
        // XON returns breaches as a nested array (sometimes 2 levels deep).
        $flat = [];
        array_walk_recursive($breaches, static function ($value) use (&$flat): void {
            if (is_string($value)) {
                $flat[] = $value;
            }
        });

        return ['breached' => $flat !== [], 'breaches' => array_values(array_unique($flat)), 'raw' => $data];
    }

    /**
     * Detailed breach analytics for an email.
     *
     * @return array<string, mixed>
     */
    public function breachAnalytics(string $email): array
    {
        $data = $this->request(self::BASE_URL.'/v1/breach-analytics?email='.rawurlencode($email));
        return is_array($data) ? $data : [];
    }

    /**
     * Anonymous password check (k-anonymity: only the first 10 chars of the
     * Keccak-512 hash leave the machine).
     *
     * @return array<string, mixed>
     */
    public function checkPassword(string $password): array
    {
        $prefix = $this->keccak512Prefix($password);
        if ($prefix === null) {
            return ['error' => 'Keccak-512 hashing is not available in this PHP build.'];
        }

        $data = $this->request(self::PASS_URL.'/api/v1/pass/anon/'.$prefix);
        return is_array($data) ? $data : [];
    }

    /**
     * First 10 chars of the SHA3 Keccak-512 hash. Requires the sodium/keccak
     * support; PHP's built-in sha3-512 is NIST-final SHA3, not original Keccak,
     * so we only use it when a keccak hash is genuinely available.
     */
    private function keccak512Prefix(string $password): ?string
    {
        if (in_array('keccak-512', hash_algos(), true)) {
            return strtoupper(substr(hash('keccak-512', $password), 0, 10));
        }

        // Fallback attempt with sha3-512 (not Keccak; may not match XON).
        if (in_array('sha3-512', hash_algos(), true)) {
            return strtoupper(substr(hash('sha3-512', $password), 0, 10));
        }

        return null;
    }

    private function request(string $url): ?array
    {
        usleep($this->throttleUs);

        try {
            $response = $this->httpClient->request('GET', $url, [
                'headers' => ['Accept' => 'application/json', 'User-Agent' => self::USER_AGENT],
                'timeout' => 25,
            ]);

            $status = $response->getStatusCode();
            $body = $response->getContent(false);

            if ($status === 404) {
                return null;
            }
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
