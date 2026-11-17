<?php

namespace App\Service;

use App\Entity\ApiFeed;
use App\Entity\Attack;
use App\Entity\DataLeak;
use App\Entity\Domain;
use App\Enum\AttackStatus;
use App\Enum\AttackType;
use App\Enum\LeakType;
use App\Enum\Severity;
use App\Repository\ApiFeedRepository;
use App\Repository\AttackRepository;
use App\Repository\DataLeakRepository;
use App\Repository\DomainRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Polls user-configured external APIs and ingests REAL attacks / leaks.
 *
 * Payload flexibility: accepts either a bare JSON array, or an object with a
 * list under any of: data, events, results, items, attacks, leaks, records.
 * Field names are auto-mapped from common conventions.
 */
class FeedSyncService
{
    public function __construct(
        private readonly ApiFeedRepository $feedRepository,
        private readonly DomainRepository $domainRepository,
        private readonly AttackRepository $attackRepository,
        private readonly DataLeakRepository $dataLeakRepository,
        private readonly EntityManagerInterface $em,
        private readonly HttpClientInterface $httpClient,
    ) {
    }

    /**
     * Sync a single feed. Returns [importedCount, message].
     *
     * @return array{0: int, 1: string}
     */
    public function sync(ApiFeed $feed): array
    {
        if (!$feed->isEnabled()) {
            $this->mark($feed, 'skipped', 'Feed disabled', 0);
            return [0, 'Feed disabled'];
        }

        try {
            $response = $this->httpClient->request(
                strtoupper((string) $feed->getHttpMethod()),
                $this->buildUrl($feed),
                [
                    'headers' => $this->buildHeaders($feed),
                    'timeout' => 20,
                ]
            );

            if ($response->getStatusCode() >= 400) {
                $msg = 'HTTP '.$response->getStatusCode();
                $this->mark($feed, 'error', $msg, 0);
                return [0, $msg];
            }

            $json = $response->getContent(false);
            $payload = json_decode($json, true);
            if (!is_array($payload)) {
                $this->mark($feed, 'error', 'Response is not valid JSON', 0);
                return [0, 'Invalid JSON'];
            }

            $items = $this->extractItems($payload);
            $imported = 0;

            foreach ($items as $item) {
                if (!is_array($item)) {
                    continue;
                }
                $saved = $feed->getKind() === ApiFeed::KIND_ATTACK
                    ? $this->importAttack($item)
                    : $this->importLeak($item);
                if ($saved) {
                    $imported++;
                }
            }

            $msg = 'Imported '.$imported.' of '.count($items).' items';
            $this->mark($feed, 'ok', $msg, $imported);

            return [$imported, $msg];
        } catch (\Throwable $e) {
            $this->mark($feed, 'error', $e->getMessage(), 0);
            return [0, $e->getMessage()];
        }
    }

    /**
     * Sync all enabled feeds.
     *
     * @return array<string, array{0: int, 1: string}>
     */
    public function syncAll(): array
    {
        $out = [];
        foreach ($this->feedRepository->findAll() as $feed) {
            $out[$feed->getKind()] = $this->sync($feed);
        }
        return $out;
    }

    /**
     * @param array<string, mixed> $payload
     * @return array<int, mixed>
     */
    private function extractItems(array $payload): array
    {
        if (array_is_list($payload)) {
            return $payload;
        }

        foreach (['data', 'events', 'results', 'items', 'attacks', 'leaks', 'records', 'rows', 'entries'] as $key) {
            if (isset($payload[$key]) && is_array($payload[$key])) {
                return array_is_list($payload[$key]) ? $payload[$key] : [$payload[$key]];
            }
        }

        return [$payload];
    }

    /**
     * @param array<string, mixed> $item
     */
    private function importAttack(array $item): bool
    {
        $type = $this->mapAttackType(
            $this->pick($item, ['type', 'attack_type', 'owasp', 'category', 'rule', 'name', 'threat'])
        );
        $severity = $this->mapSeverity($this->pick($item, ['severity', 'level', 'priority', 'risk']));
        $status = $this->mapAttackStatus($this->pick($item, ['status', 'action', 'disposition', 'verdict']));

        $externalId = $this->pick($item, ['id', 'event_id', 'uuid', 'alert_id']);
        $detectedAt = $this->parseDate($this->pick($item, ['detected_at', 'timestamp', 'time', 'date', 'created_at', 'occurred_at']));

        $fingerprint = $this->fingerprint($item, $externalId);
        $exists = $this->em->getRepository(Attack::class)->findOneBy(['fingerprint' => $fingerprint]);
        if ($exists !== null) {
            return false;
        }

        $attack = new Attack();
        $attack->setDomain($this->resolveDomain($item));
        $attack->setType($type);
        $attack->setSeverity($severity);
        $attack->setStatus($status);
        $attack->setSourceIp($this->str($this->pick($item, ['source_ip', 'ip', 'src_ip', 'remote_addr', 'client_ip'])));
        $attack->setEndpoint($this->str($this->pick($item, ['endpoint', 'url', 'path', 'request_uri', 'request'])));
        $attack->setHttpMethod($this->str($this->pick($item, ['http_method', 'method', 'verb'])));
        $attack->setCountry($this->str($this->pick($item, ['country', 'geo_country', 'geo'])));
        $attack->setUserAgent($this->str($this->pick($item, ['user_agent', 'ua'])));
        $attack->setPayload(isset($item['payload']) ? (string) json_encode($item['payload']) : mb_substr((string) json_encode($item), 0, 2000));
        $attack->setFingerprint($fingerprint);
        $attack->setDetectedAt($detectedAt ?? new \DateTimeImmutable());

        $this->em->persist($attack);
        $this->em->flush();

        return true;
    }

    /**
     * @param array<string, mixed> $item
     */
    private function importLeak(array $item): bool
    {
        $type = $this->mapLeakType(
            $this->pick($item, ['type', 'leak_type', 'category', 'kind', 'datatype', 'data_type'])
        );
        $severity = $this->mapSeverity($this->pick($item, ['severity', 'level', 'priority', 'risk']));
        $detectedAt = $this->parseDate($this->pick($item, ['detected_at', 'timestamp', 'time', 'date', 'created_at', 'found_at']));

        $externalId = $this->pick($item, ['id', 'record_id', 'uuid']);
        $dataSample = $this->pick($item, ['data_sample', 'sample', 'data', 'value', 'content', 'record']);
        if ($dataSample === null) {
            $dataSample = mb_substr((string) json_encode($item), 0, 2000);
        }

        $signature = $this->fingerprint($item, $externalId);
        $exists = $this->em->getRepository(DataLeak::class)->findOneBy(['fingerprint' => $signature]);
        if ($exists !== null) {
            return false;
        }

        $leak = new DataLeak();
        $leak->setDomain($this->resolveDomain($item));
        $leak->setType($type);
        $leak->setSeverity($severity);
        $leak->setDataSample(is_scalar($dataSample) ? (string) $dataSample : json_encode($dataSample));
        $leak->setSource($this->str($this->pick($item, ['source', 'source_name', 'origin', 'site', 'forum'])));
        $leak->setEmail($this->str($this->pick($item, ['email', 'mail', 'username', 'account'])));
        $leak->setIpAddress($this->str($this->pick($item, ['ip', 'ip_address', 'source_ip'])));
        $leak->setCountry($this->str($this->pick($item, ['country', 'geo_country', 'geo'])));
        $leak->setFingerprint($signature);
        $leak->setDetectedAt($detectedAt ?? new \DateTimeImmutable());

        $this->em->persist($leak);
        $this->em->flush();

        return true;
    }

    private function resolveDomain(array $item): Domain
    {
        $domainName = $this->str($this->pick($item, ['domain', 'site', 'host', 'hostname', 'asset']));
        if ($domainName !== null) {
            $domain = $this->domainRepository->findOneBy(['name' => $domainName]);
            if ($domain !== null) {
                return $domain;
            }
        }

        $domain = $this->domainRepository->findOneBy([]);
        if ($domain === null) {
            $domain = new Domain();
            $domain->setName($domainName ?? 'unassigned.local')
                ->setApiKey(bin2hex(random_bytes(16)))
                ->setMonitoringEnabled(true);
            $this->em->persist($domain);
            $this->em->flush();
        }

        return $domain;
    }

    private function buildUrl(ApiFeed $feed): string
    {
        $url = (string) $feed->getEndpointUrl();
        $qs = trim((string) $feed->getQueryParams());
        if ($qs !== '') {
            $url .= (str_contains($url, '?') ? '&' : '?').ltrim($qs, '?');
        }
        return $url;
    }

    /**
     * @return array<string, string>
     */
    private function buildHeaders(ApiFeed $feed): array
    {
        $headers = ['Accept' => 'application/json', 'User-Agent' => 'WatchLeaks-FeedSync/1.0'];
        $token = $feed->getAuthToken();
        if ($token !== null && $token !== '') {
            $headerName = $feed->getAuthHeaderName() ?: 'Authorization';
            $headers[$headerName] = str_starts_with(strtolower($headerName), 'authorization') && !preg_match('/^(bearer|basic|token)\s/i', $token)
                ? 'Bearer '.$token
                : $token;
        }
        return $headers;
    }

    /**
     * @param array<string, mixed> $item
     * @param string[] $keys
     */
    private function pick(array $item, array $keys): mixed
    {
        foreach ($keys as $key) {
            if (array_key_exists($key, $item) && $item[$key] !== null && $item[$key] !== '') {
                return $item[$key];
            }
        }
        // case-insensitive fallback
        $lower = array_change_key_case($item, CASE_LOWER);
        foreach ($keys as $key) {
            if (array_key_exists(strtolower($key), $lower) && $lower[strtolower($key)] !== null && $lower[strtolower($key)] !== '') {
                return $lower[strtolower($key)];
            }
        }
        return null;
    }

    private function fingerprint(array $item, mixed $externalId): string
    {
        if ($externalId !== null && $externalId !== '') {
            return md5('ext:'.$externalId);
        }

        return md5(json_encode([
            $this->pick($item, ['source_ip', 'ip', 'src_ip', 'remote_addr', 'client_ip', 'email', 'mail', 'username']),
            $this->pick($item, ['endpoint', 'url', 'path', 'request_uri', 'request', 'source', 'source_name', 'data_sample', 'sample', 'data']),
            $this->pick($item, ['detected_at', 'timestamp', 'time', 'date', 'created_at', 'found_at']),
        ]));
    }

    private function str(mixed $v): ?string
    {
        if ($v === null) return null;
        if (is_scalar($v)) return mb_substr((string) $v, 0, 255);
        return mb_substr((string) json_encode($v), 0, 255);
    }

    private function parseDate(mixed $v): ?\DateTimeImmutable
    {
        if ($v === null || $v === '') return null;
        if (is_numeric($v)) {
            $ts = (int) $v;
            return new \DateTimeImmutable('@'.$ts);
        }
        try {
            return new \DateTimeImmutable((string) $v);
        } catch (\Throwable) {
            return null;
        }
    }

    private function mapSeverity(mixed $v): Severity
    {
        $s = strtolower(trim((string) $v));
        return match (true) {
            in_array($s, ['critical', 'crit', 'sev1', 'p1', 'urgent', '4'], true) => Severity::CRITICAL,
            in_array($s, ['high', 'sev2', 'p2', 'major', '3'], true) => Severity::HIGH,
            in_array($s, ['medium', 'med', 'moderate', 'sev3', 'p3', '2'], true) => Severity::MEDIUM,
            in_array($s, ['low', 'sev4', 'p4', 'minor', 'info', '1'], true) => Severity::LOW,
            default => Severity::HIGH,
        };
    }

    private function mapAttackType(mixed $v): AttackType
    {
        $t = strtolower(trim((string) $v));
        return match (true) {
            str_contains($t, 'a01') || str_contains($t, 'access') || str_contains($t, 'idor') || str_contains($t, 'traversal') => AttackType::A01_BROKEN_ACCESS,
            str_contains($t, 'a02') || str_contains($t, 'crypto') || str_contains($t, 'ssl') || str_contains($t, 'tls') => AttackType::A02_CRYPTO_FAILURES,
            str_contains($t, 'a03') || str_contains($t, 'sql') || str_contains($t, 'inject') || str_contains($t, 'xss') || str_contains($t, 'cmdi') => AttackType::A03_INJECTION,
            str_contains($t, 'a04') || str_contains($t, 'insecure design') || str_contains($t, 'business logic') => AttackType::A04_INSECURE_DESIGN,
            str_contains($t, 'a05') || str_contains($t, 'misconfig') || str_contains($t, 'exposure') || str_contains($t, 'default') => AttackType::A05_MISCONFIGURATION,
            str_contains($t, 'a06') || str_contains($t, 'outdated') || str_contains($t, 'component') || str_contains($t, 'cve') => AttackType::A06_VULNERABLE_COMPONENTS,
            str_contains($t, 'a07') || str_contains($t, 'auth') || str_contains($t, 'brute') || str_contains($t, 'credential stuffing') || str_contains($t, 'session') => AttackType::A07_AUTH_FAILURES,
            str_contains($t, 'a08') || str_contains($t, 'integrity') || str_contains($t, 'deserial') || str_contains($t, 'ci/cd') => AttackType::A08_INTEGRITY_FAILURES,
            str_contains($t, 'a09') || str_contains($t, 'logging') || str_contains($t, 'monitoring') || str_contains($t, 'audit') => AttackType::A09_LOGGING_FAILURES,
            str_contains($t, 'a10') || str_contains($t, 'ssrf') || str_contains($t, 'server-side request') => AttackType::A10_SSRF,
            default => AttackType::A03_INJECTION,
        };
    }

    private function mapLeakType(mixed $v): LeakType
    {
        $t = strtolower(trim((string) $v));
        return match (true) {
            str_contains($t, 'password') || str_contains($t, 'passwd') || str_contains($t, 'hash') => LeakType::PASSWORD,
            str_contains($t, 'credential') || str_contains($t, 'login') => LeakType::CREDENTIALS,
            str_contains($t, 'database') || str_contains($t, 'dump') || str_contains($t, 'sql') => LeakType::DATABASE,
            str_contains($t, 'api') || str_contains($t, 'key') || str_contains($t, 'token') || str_contains($t, 'secret') => LeakType::API_KEY,
            str_contains($t, 'financial') || str_contains($t, 'card') || str_contains($t, 'credit') || str_contains($t, 'cc') => LeakType::FINANCIAL,
            str_contains($t, 'personal') || str_contains($t, 'pii') || str_contains($t, 'ssn') || str_contains($t, 'identity') => LeakType::PERSONAL_DATA,
            str_contains($t, 'email') || str_contains($t, 'mail') => LeakType::EMAIL,
            default => LeakType::PERSONAL_DATA,
        };
    }

    private function mapAttackStatus(mixed $v): AttackStatus
    {
        $s = strtolower(trim((string) $v));
        return match (true) {
            in_array($s, ['blocked', 'dropped', 'denied', 'rejected', 'mitigated', 'blocked_by_waf'], true) => AttackStatus::BLOCKED,
            in_array($s, ['investigating', 'triage', 'review', 'acknowledged'], true) => AttackStatus::INVESTIGATING,
            in_array($s, ['mitigated', 'resolved', 'closed'], true) => AttackStatus::MITIGATED,
            default => AttackStatus::DETECTED,
        };
    }

    private function mark(ApiFeed $feed, string $status, string $message, int $imported): void
    {
        $feed->setLastStatus($status)
            ->setLastMessage($message)
            ->setLastImportedCount($imported)
            ->setLastSyncedAt(new \DateTimeImmutable());
        $this->em->flush();
    }
}
