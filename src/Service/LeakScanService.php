<?php

namespace App\Service;

use App\Entity\DataLeak;
use App\Entity\Domain;
use App\Enum\LeakType;
use App\Enum\Severity;
use App\Repository\DataLeakRepository;
use App\Repository\DomainRepository;
use Doctrine\ORM\EntityManagerInterface;

/**
 * Scans monitored domains against the XposedOrNot breach database and
 * imports each real breach as a DataLeak record (deduplicated).
 */
class LeakScanService
{
    /** @var array<string, array<int, array<string, mixed>>> */
    private array $victimCache = [];

    /** @var array<string, array<int, array<string, mixed>>> */
    private array $usernameCache = [];

    /** @var array<int, array<string, mixed>>|null */
    private ?array $authenticatedBreaches = null;

    public function __construct(
        private readonly XposedOrNotClient $xon,
        private readonly RansomwareLiveClient $ransomware,
        private readonly HudsonRockClient $hudsonRock,
        private readonly LeakRadarClient $leakRadar,
        private readonly SettingsService $settings,
        private readonly DomainRepository $domainRepository,
        private readonly DataLeakRepository $dataLeakRepository,
        private readonly EntityManagerInterface $em,
    ) {
    }

    /**
     * Scan every monitored domain. Returns [domainsScanned, leaksImported].
     *
     * @return array{0: int, 1: int}
     */
    public function scanAll(): array
    {
        $domains = $this->domainRepository->findBy(['monitoringEnabled' => true]);
        $imported = 0;

        foreach ($domains as $domain) {
            $imported += $this->scanDomain($domain);
        }

        return [count($domains), $imported];
    }

    public function scanDomain(Domain $domain): int
    {
        $name = $domain->getName();
        if ($name === null || $name === '') {
            return 0;
        }

        // Strip scheme/leading www if a URL was entered as the domain name.
        $host = preg_replace('#^https?://#i', '', $name);
        $host = preg_replace('#^www\.#i', '', (string) $host);
        $host = strtok((string) $host, '/');

        $breaches = $this->xon->breachesByDomain((string) $host);
        $imported = 0;

        foreach ($breaches as $breach) {
            if (!is_array($breach)) {
                continue;
            }
            if ($this->importBreach($domain, $breach)) {
                $imported++;
            }
        }

        // Authenticated XposedOrNot domain breaches (requires an API key).
        foreach ($this->authenticatedBreaches() as $breach) {
            if (!is_array($breach)) {
                continue;
            }
            $breachDomain = strtolower(trim((string) ($breach['domain'] ?? '')));
            if ($breachDomain !== '' && !$this->domainMatches($breachDomain, (string) $host)) {
                continue;
            }
            if ($this->importBreach($domain, $breach)) {
                $imported++;
            }
        }

        // Real-time ransomware leak-site feed (ransomware.live).
        $label = strstr((string) $host, '.', true) ?: (string) $host;
        $keywords = [$label];
        // Also try the first hyphen-token (e.g. "outsourcia-group" -> "outsourcia").
        $token = strstr($label, '-', true);
        if (is_string($token) && strlen($token) >= 4) {
            $keywords[] = $token;
        }
        foreach (array_unique(array_filter($keywords)) as $keyword) {
            foreach ($this->searchVictimsCached($keyword) as $victim) {
                if (is_array($victim) && $this->importRansomwareVictim($domain, $victim)) {
                    $imported++;
                }
            }
        }

        // Real-time infostealer credentials feed (Hudson Rock Cavalier).
        $imported += $this->importHudsonRock($domain, (string) $host) ? 1 : 0;

        // Credential exposure across Telegram stealer logs / forums / combolists.
        $imported += $this->importLeakRadar($domain, (string) $host) ? 1 : 0;

        $domain->setLastScanAt(new \DateTimeImmutable());
        $this->em->flush();

        return $imported;
    }

    /**
     * @param array<string, mixed> $breach
     */
    private function importBreach(Domain $domain, array $breach): bool
    {
        $breachId = (string) ($breach['breachID'] ?? $breach['breach'] ?? $breach['name'] ?? '');
        $breachedDomain = (string) ($breach['domain'] ?? '');
        if ($breachId === '') {
            $breachId = md5(json_encode($breach));
        }

        $fingerprint = md5('xon:'.strtolower($breachId).':'.strtolower($breachedDomain));
        if ($this->dataLeakRepository->findOneBy(['fingerprint' => $fingerprint]) !== null) {
            return false;
        }

        $exposedData = $breach['exposedData'] ?? $breach['xposed_data'] ?? [];
        if (is_string($exposedData)) {
            $exposedData = array_map('trim', explode(';', $exposedData));
        }
        $exposedData = is_array($exposedData) ? $exposedData : [];

        $records = (int) ($breach['exposedRecords'] ?? $breach['xposed_records'] ?? 0);
        $passwordRisk = strtolower((string) ($breach['passwordRisk'] ?? $breach['password_risk'] ?? ''));

        $leak = new DataLeak();
        $leak->setDomain($domain);
        $leak->setType($this->mapType($exposedData));
        $leak->setSeverity($this->mapSeverity($records, $passwordRisk));
        $leak->setSource($breachId);
        $leak->setCountry(null);
        $leak->setFingerprint($fingerprint);

        $description = (string) ($breach['exposureDescription'] ?? $breach['xposure_desc'] ?? '');
        $summary = sprintf(
            '%s breach (%s) — %s records. Exposed: %s. %s',
            $breachId,
            $breachedDomain ?: $domain->getName(),
            number_format($records),
            $exposedData ? implode(', ', $exposedData) : 'unknown',
            trim($description)
        );
        $leak->setDataSample(mb_substr($summary, 0, 2000));

        $date = $breach['breachedDate'] ?? $breach['breached_date'] ?? $breach['addedDate'] ?? null;
        $detectedAt = $this->parseDate($date);
        $leak->setDetectedAt($detectedAt ?? new \DateTimeImmutable());

        $this->em->persist($leak);
        $this->em->flush();

        return true;
    }

    /**
     * Import (or refresh) infostealer credential data for a domain from
     * Hudson Rock. One aggregated leak record is kept per domain and updated.
     *
     * @return bool true when a new record was created
     */
    private function importHudsonRock(Domain $domain, string $host): bool
    {
        $data = $this->hudsonRock->domain($host);
        $total = (int) ($data['total'] ?? 0);
        if ($total <= 0) {
            return false;
        }

        $employees = (int) ($data['employees'] ?? 0);
        $users = (int) ($data['users'] ?? 0);
        $thirdParties = (int) ($data['third_parties'] ?? 0);

        $urls = $data['data']['all_urls'] ?? [];
        $urlSummary = [];
        if (is_array($urls)) {
            foreach (array_slice($urls, 0, 8) as $row) {
                if (!is_array($row)) {
                    continue;
                }
                $urlSummary[] = sprintf(
                    '%s (x%d, %s)',
                    (string) ($row['url'] ?? ''),
                    (int) ($row['occurrence'] ?? 0),
                    (string) ($row['type'] ?? '')
                );
            }
        }

        $sample = mb_substr(trim(sprintf(
            'Information-stealer infections (Hudson Rock): %d total — %d employee, %d user, %d third-party. Infected hosts: %s',
            $total,
            $employees,
            $users,
            $thirdParties,
            $urlSummary ? implode('; ', $urlSummary) : 'n/a'
        )), 0, 2000);

        // Attach stealer-log credential exposures (logins/passwords as masked
        // by the free Hudson Rock API) matched to this domain.
        $credInfo = $this->stealerCredentials($host);
        if ($credInfo['count'] > 0) {
            $sample = mb_substr($sample."\n\n".$credInfo['text'], 0, 4000);
        }

        $severity = $employees > 0 ? Severity::CRITICAL : Severity::HIGH;
        $fingerprint = md5('hudsonrock:'.strtolower($domain->getName() ?? $host));

        $existing = $this->dataLeakRepository->findOneBy(['fingerprint' => $fingerprint]);
        if ($existing !== null) {
            $existing->setDataSample($sample);
            $existing->setSeverity($severity);
            $existing->setDetectedAt(new \DateTimeImmutable());
            $this->em->flush();

            return false;
        }

        $leak = new DataLeak();
        $leak->setDomain($domain);
        $leak->setType(LeakType::CREDENTIALS);
        $leak->setSeverity($severity);
        $leak->setSource('Hudson Rock (infostealer)');
        $leak->setFingerprint($fingerprint);
        $leak->setDataSample($sample);
        $leak->setDetectedAt(new \DateTimeImmutable());

        $this->em->persist($leak);
        $this->em->flush();

        return true;
    }

    /**
     * Credential exposure for a domain across Telegram stealer logs, dark-web
     * forums and combolists (LeakRadar).
     *
     * Aggregate counts are public; listing the actual url/user/password
     * records requires an API key (Settings → LeakRadar).
     *
     * @return bool true when a new record was created
     */
    private function importLeakRadar(Domain $domain, string $host): bool
    {
        $report = $this->leakRadar->report($host);
        if (!$report) {
            return false;
        }

        $employees = (int) ($report['employees_compromised'] ?? 0);
        $thirdParties = (int) ($report['third_parties_compromised'] ?? 0);
        $customers = (int) ($report['customers_compromised'] ?? 0);
        $stealerTotal = $employees + $thirdParties + $customers;

        $combo = $this->leakRadar->combolistReport($host);
        $comboPairs = (int) ($combo['total_credentials'] ?? 0);
        $comboEmails = (int) ($combo['unique_emails'] ?? 0);

        if ($stealerTotal <= 0 && $comboPairs <= 0) {
            return false;
        }

        $lines = ['LeakRadar exposure (Telegram stealer logs, dark-web forums and combolists):'];
        if ($stealerTotal > 0) {
            $lines[] = sprintf(
                '• Stealer logs: %d credential(s) — %d employee, %d customer, %d third-party.',
                $stealerTotal,
                $employees,
                $customers,
                $thirdParties
            );
        }
        if ($comboPairs > 0) {
            $strength = is_array($combo['password_strength'] ?? null) ? $combo['password_strength'] : [];
            $lines[] = sprintf(
                '• Combolists: %d credential pair(s) across %d unique email(s). Password strength — too weak %d, weak %d, medium %d, strong %d. Observed %s → %s.',
                $comboPairs,
                $comboEmails,
                (int) ($strength['too_weak'] ?? 0),
                (int) ($strength['weak'] ?? 0),
                (int) ($strength['medium'] ?? 0),
                (int) ($strength['strong'] ?? 0),
                $this->formatDate($combo['first_seen'] ?? null),
                $this->formatDate($combo['last_seen'] ?? null)
            );
        }

        $email = null;
        $records = $this->leakRadar->allLeaks($host, 1, 20)
            ?? $this->leakRadar->combolistLeaks($host, 1, 20);

        if ($records !== null && $records['total'] > 0) {
            $lines[] = sprintf('• Recorded credentials (%d total, %d unlocked):', $records['total'], $records['unlocked']);
            $sampled = 0;
            foreach ($records['items'] as $item) {
                if (!is_array($item)) {
                    continue;
                }
                $user = (string) ($item['username'] ?? '');
                $pass = (string) ($item['password'] ?? '');
                $url = (string) ($item['url'] ?? '');
                if ($user === '' && $pass === '') {
                    continue;
                }
                if ($email === null && str_contains($user, '@')) {
                    $email = $user;
                }
                $lines[] = sprintf('   - %s | %s | %s', $url ?: 'n/a', $user ?: 'n/a', $pass !== '' ? $pass : 'locked');
                if (++$sampled >= 15) {
                    break;
                }
            }
        } elseif (!$this->leakRadar->hasApiKey()) {
            $lines[] = '• Add a LeakRadar API key in Settings to list the individual email/password records.';
        }

        $severity = ($employees > 0 || $comboPairs > 0) ? Severity::CRITICAL : Severity::HIGH;
        $sample = mb_substr(implode("\n", $lines), 0, 4000);
        $fingerprint = md5('leakradar:'.strtolower($host));
        $lastSeen = $combo['last_seen'] ?? null;
        $detectedAt = $this->parseDate($lastSeen) ?? new \DateTimeImmutable();

        $existing = $this->dataLeakRepository->findOneBy(['fingerprint' => $fingerprint]);
        if ($existing !== null) {
            $existing->setDataSample($sample);
            $existing->setSeverity($severity);
            if ($email !== null) {
                $existing->setEmail($email);
            }
            $existing->setDetectedAt($detectedAt);
            $this->em->flush();

            return false;
        }

        $leak = new DataLeak();
        $leak->setDomain($domain);
        $leak->setType(LeakType::CREDENTIALS);
        $leak->setSeverity($severity);
        $leak->setSource('LeakRadar (stealer logs / combolists)');
        $leak->setFingerprint($fingerprint);
        $leak->setDataSample($sample);
        $leak->setEmail($email);
        $leak->setDetectedAt($detectedAt);

        $this->em->persist($leak);
        $this->em->flush();

        return true;
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    private function authenticatedBreaches(): array
    {
        if ($this->authenticatedBreaches !== null) {
            return $this->authenticatedBreaches;
        }

        $key = $this->settings->get(SettingsService::XON_API_KEY);
        if ($key === null || trim($key) === '') {
            return $this->authenticatedBreaches = [];
        }

        return $this->authenticatedBreaches = $this->xon->domainBreaches(trim($key));
    }

    private function domainMatches(string $candidate, string $host): bool
    {
        $normalize = static fn (string $value): string => strtolower(rtrim((string) preg_replace('#^https?://#i', '', $value), '/'));
        $candidate = $normalize($candidate);
        $host = $normalize($host);
        $candidate = (string) preg_replace('#^www\.#i', '', $candidate);
        $host = (string) preg_replace('#^www\.#i', '', $host);

        return $candidate === $host
            || str_ends_with($candidate, '.'.$host)
            || str_ends_with($host, '.'.$candidate);
    }

    private function formatDate(?string $value): string
    {
        if ($value === null || $value === '') {
            return 'n/a';
        }
        try {
            return (new \DateTimeImmutable($value))->format('Y-m-d');
        } catch (\Exception) {
            return $value;
        }
    }

    /**
     * Collect infostealer logs whose saved logins reference the given host.
     *
     * Hudson Rock's free API masks credentials; this surfaces the matched
     * stealer entries (host, OS, date and masked logins/passwords).
     *
     * @return array{count: int, text: string}
     */
    private function stealerCredentials(string $host): array
    {
        $label = strstr($host, '.', true) ?: $host;
        $host = strtolower($host);
        $label = strtolower($label);

        $queries = array_values(array_unique(array_filter([$label, strstr($label, '-', true) ?: null])));
        $stealers = [];

        foreach ($queries as $query) {
            if (!isset($this->usernameCache[$query])) {
                try {
                    $resp = $this->hudsonRock->username($query);
                    $this->usernameCache[$query] = is_array($resp['stealers'] ?? null) ? $resp['stealers'] : [];
                } catch (\Throwable) {
                    $this->usernameCache[$query] = [];
                }
            }
            foreach ($this->usernameCache[$query] as $stealer) {
                if (!is_array($stealer)) {
                    continue;
                }
                $logins = array_filter((array) ($stealer['top_logins'] ?? []), 'is_string');
                $matches = false;
                foreach ($logins as $login) {
                    $l = strtolower($login);
                    if (str_contains($l, '@'.$host) || str_contains($l, $label)) {
                        $matches = true;
                        break;
                    }
                }
                if ($matches) {
                    $key = md5((string) json_encode([$stealer['date_compromised'] ?? '', $logins]));
                    $stealers[$key] = $stealer;
                }
            }
        }

        if (!$stealers) {
            return ['count' => 0, 'text' => ''];
        }

        $lines = [sprintf(
            'Credential exposures in stealer logs (logins/passwords masked by Hudson Rock free API) — %d matched log(s):',
            count($stealers)
        )];
        foreach (array_slice(array_values($stealers), 0, 6) as $s) {
            $lines[] = sprintf(
                '• %s · %s · %s · logins: %s | passwords: %s',
                (string) ($s['date_compromised'] ?? 'n/a'),
                (string) ($s['operating_system'] ?? 'n/a'),
                (string) ($s['computer_name'] ?? 'n/a'),
                implode(', ', array_filter((array) ($s['top_logins'] ?? []), 'is_string')) ?: 'n/a',
                implode(', ', array_filter((array) ($s['top_passwords'] ?? []), 'is_string')) ?: 'n/a'
            );
        }

        return ['count' => count($stealers), 'text' => implode("\n", $lines)];
    }

    /**
     * Cached ransomware.live search (avoids duplicate API calls in one scan run).
     *
     * @return array<int, array<string, mixed>>
     */
    private function searchVictimsCached(string $keyword): array
    {
        $key = strtolower(trim($keyword));
        if (!array_key_exists($key, $this->victimCache)) {
            $this->victimCache[$key] = $this->ransomware->searchVictims($keyword);
        }

        return $this->victimCache[$key];
    }

    /**
     * Import a ransomware leak-site victim listing as a DataLeak (deduplicated).
     *
     * @param array<string, mixed> $victim
     */
    private function importRansomwareVictim(Domain $domain, array $victim): bool
    {
        $group = trim((string) ($victim['group'] ?? $victim['gang'] ?? 'unknown'));
        $victimName = trim((string) ($victim['victim'] ?? $victim['post_title'] ?? ''));
        $attackDate = (string) ($victim['attackdate'] ?? $victim['discovered'] ?? '');
        $listedDomain = trim((string) ($victim['domain'] ?? ''));

        if ($victimName === '' && $listedDomain === '') {
            return false;
        }

        // The ransomware.live search is full-text, so only keep victims that
        // genuinely correspond to this domain (by listed domain or exact name).
        $norm = static fn (string $s): string => (string) preg_replace('/[^a-z0-9]/', '', strtolower($s));

        $hostClean = strtolower((string) preg_replace('#^https?://#', '', $domain->getName() ?? ''));
        $hostClean = (string) preg_replace('#^www\.#', '', $hostClean);
        $hostClean = strtolower((string) strtok($hostClean, '/'));
        $hostLabel = strstr($hostClean, '.', true) ?: $hostClean;

        $listedClean = strtolower((string) preg_replace('#^https?://#', '', $listedDomain));
        $listedClean = (string) preg_replace('#^www\.#', '', $listedClean);
        $listedClean = rtrim($listedClean, '/');

        $victimNorm = $norm($victimName);
        $labelNorm = $norm((string) $hostLabel);

        $domainMatch = $listedClean !== '' && $hostClean !== '' && (
            $listedClean === $hostClean
            || str_ends_with($listedClean, '.'.$hostClean)
            || str_ends_with($hostClean, '.'.$listedClean)
        );
        $nameMatch = $victimNorm !== '' && $labelNorm !== '' && (
            $victimNorm === $labelNorm
            || (strlen($victimNorm) >= 5 && str_starts_with($labelNorm, $victimNorm))
        );

        if (!$domainMatch && !$nameMatch) {
            return false;
        }

        $fingerprint = md5('ransomware:'.strtolower($group.':'.$victimName.':'.$attackDate.':'.$domain->getName()));
        if ($this->dataLeakRepository->findOneBy(['fingerprint' => $fingerprint]) !== null) {
            return false;
        }

        $leak = new DataLeak();
        $leak->setDomain($domain);
        $leak->setType(LeakType::DATABASE);
        $leak->setSeverity(Severity::CRITICAL);
        $leak->setSource($group.' ransomware');
        $leak->setCountry(trim((string) ($victim['country'] ?? '')) ?: null);
        $leak->setFingerprint($fingerprint);

        $parts = [
            sprintf('Ransomware victim listed by group "%s".', $group),
            $victimName !== '' ? 'Victim: '.$victimName.'.' : '',
            $listedDomain !== '' ? 'Listed domain: '.$listedDomain.'.' : '',
            ($victim['activity'] ?? '') !== '' ? 'Industry: '.$victim['activity'].'.' : '',
            ($victim['country'] ?? '') !== '' ? 'Country: '.$victim['country'].'.' : '',
            $attackDate !== '' ? 'Listed: '.$attackDate.'.' : '',
            ($victim['claim_url'] ?? '') !== '' ? 'Leak site: '.$victim['claim_url'] : '',
            'Source: ransomware.live',
        ];
        $leak->setDataSample(mb_substr(trim(implode(' ', array_filter($parts))), 0, 2000));

        $detectedAt = $this->parseDate($attackDate);
        $leak->setDetectedAt($detectedAt ?? new \DateTimeImmutable());

        $this->em->persist($leak);
        $this->em->flush();

        return true;
    }

    /**
     * @param array<int, mixed> $exposedData
     */
    private function mapType(array $exposedData): LeakType
    {
        $joined = strtolower(implode(' ', array_map(static fn ($x) => is_string($x) ? $x : '', $exposedData)));

        return match (true) {
            str_contains($joined, 'password') => LeakType::PASSWORD,
            str_contains($joined, 'credential') || str_contains($joined, 'login') => LeakType::CREDENTIALS,
            str_contains($joined, 'financial') || str_contains($joined, 'credit') || str_contains($joined, 'payment') => LeakType::FINANCIAL,
            str_contains($joined, 'ssn') || str_contains($joined, 'passport') || str_contains($joined, 'national') || str_contains($joined, 'identity') => LeakType::PERSONAL_DATA,
            str_contains($joined, 'email') => LeakType::EMAIL,
            $joined === '' => LeakType::PERSONAL_DATA,
            default => LeakType::PERSONAL_DATA,
        };
    }

    private function mapSeverity(int $records, string $passwordRisk): Severity
    {
        if ($records >= 1_000_000) {
            return Severity::CRITICAL;
        }
        if ($records >= 100_000) {
            return Severity::HIGH;
        }
        if (in_array($passwordRisk, ['plaintext', 'easytocrack'], true)) {
            return Severity::HIGH;
        }
        if ($records >= 10_000) {
            return Severity::HIGH;
        }
        if ($records >= 1_000) {
            return Severity::MEDIUM;
        }
        return Severity::LOW;
    }

    private function parseDate(mixed $value): ?\DateTimeImmutable
    {
        if ($value === null || $value === '') {
            return null;
        }
        try {
            return new \DateTimeImmutable((string) $value);
        } catch (\Throwable) {
            return null;
        }
    }
}
