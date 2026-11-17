<?php

namespace App\Controller;

use App\Entity\Attack;
use App\Entity\DataLeak;
use App\Enum\AttackStatus;
use App\Enum\AttackType;
use App\Enum\LeakType;
use App\Enum\Severity;
use App\Repository\AttackRepository;
use App\Repository\DataLeakRepository;
use App\Repository\DomainRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

#[Route('/api')]
class ApiController extends AbstractController
{
    public function __construct(
        private readonly DomainRepository $domainRepository,
        private readonly DataLeakRepository $dataLeakRepository,
        private readonly AttackRepository $attackRepository,
        private readonly EntityManagerInterface $em,
    ) {
    }

    /**
     * Ingest a data leak report. Authenticated via X-API-Key header.
     */
    #[Route('/ingest/leak', name: 'app_api_ingest_leak', methods: ['POST'])]
    public function ingestLeak(Request $request): JsonResponse
    {
        $domain = $this->resolveDomain($request);
        if ($domain === null) {
            return $this->json(['success' => false, 'error' => 'Invalid API key or domain inactive.'], Response::HTTP_UNAUTHORIZED);
        }

        $payload = $this->decodeJson($request);
        if ($payload === null) {
            return $this->json(['success' => false, 'error' => 'Invalid JSON body.'], Response::HTTP_BAD_REQUEST);
        }

        $leak = new DataLeak();
        $leak->setDomain($domain);
        $leak->setType(LeakType::tryFrom($this->field($payload, 'type', 32) ?? 'email') ?? LeakType::EMAIL);
        $leak->setSeverity(Severity::tryFrom($this->field($payload, 'severity', 32) ?? 'medium') ?? Severity::MEDIUM);
        $leak->setDataSample($this->field($payload, 'dataSample', 2000) ?? '');
        $leak->setSource($this->field($payload, 'source', 255));
        $leak->setEmail($this->email($payload));
        $leak->setIpAddress($this->ip($payload));
        $leak->setCountry($this->field($payload, 'country', 100));

        $domain->setLastScanAt(new \DateTimeImmutable());
        $this->em->persist($leak);
        $this->em->flush();

        return $this->json(['success' => true, 'id' => $leak->getId()], Response::HTTP_CREATED);
    }

    /**
     * Ingest a detected attack event. Authenticated via X-API-Key header.
     */
    #[Route('/ingest/attack', name: 'app_api_ingest_attack', methods: ['POST'])]
    public function ingestAttack(Request $request): JsonResponse
    {
        $domain = $this->resolveDomain($request);
        if ($domain === null) {
            return $this->json(['success' => false, 'error' => 'Invalid API key or domain inactive.'], Response::HTTP_UNAUTHORIZED);
        }

        $payload = $this->decodeJson($request);
        if ($payload === null) {
            return $this->json(['success' => false, 'error' => 'Invalid JSON body.'], Response::HTTP_BAD_REQUEST);
        }

        $attack = new Attack();
        $attack->setDomain($domain);
        $attack->setType(AttackType::tryFrom($this->field($payload, 'type', 32) ?? 'A03') ?? AttackType::A03_INJECTION);
        $attack->setSeverity(Severity::tryFrom($this->field($payload, 'severity', 32) ?? 'high') ?? Severity::HIGH);
        $attack->setStatus(AttackStatus::tryFrom($this->field($payload, 'status', 32) ?? 'detected') ?? AttackStatus::DETECTED);
        $attack->setSourceIp($this->ip($payload, 'sourceIp'));
        $attack->setEndpoint($this->field($payload, 'endpoint', 255));
        $attack->setHttpMethod($this->field($payload, 'httpMethod', 16));
        $attack->setCountry($this->field($payload, 'country', 100));
        $attack->setUserAgent($this->field($payload, 'userAgent', 500));
        $attack->setPayload($this->field($payload, 'payload', 4000));

        $domain->setLastScanAt(new \DateTimeImmutable());
        $this->em->persist($attack);
        $this->em->flush();

        return $this->json(['success' => true, 'id' => $attack->getId()], Response::HTTP_CREATED);
    }

    /**
     * Real-time feed: returns recent attacks + leaks since a timestamp (for polling).
     */
    #[Route('/feed', name: 'app_api_feed', methods: ['GET'])]
    public function feed(Request $request, \App\Service\DomainContext $domainContext): JsonResponse
    {
        $domainIds = $domainContext->scopedDomainIds();

        $sinceParam = $request->query->get('since');
        $since = is_string($sinceParam) ? \DateTimeImmutable::createFromFormat(\DateTimeInterface::ATOM, $sinceParam) : false;

        $sinceDate = $since instanceof \DateTimeImmutable ? $since : null;
        $recentAttacks = $this->attackRepository->findRecent($domainIds, 20, $sinceDate);
        $recentLeaks = $this->dataLeakRepository->findRecentLeaks($domainIds, 20, $sinceDate);

        return $this->json([
            'serverTime' => (new \DateTimeImmutable())->format(\DateTimeInterface::ATOM),
            'attacks' => array_map(static fn (Attack $a) => [
                'id' => $a->getId(),
                'type' => $a->getType()?->value,
                'typeLabel' => $a->getType()?->label(),
                'severity' => $a->getSeverity()->value,
                'status' => $a->getStatus()->value,
                'sourceIp' => $a->getSourceIp(),
                'endpoint' => $a->getEndpoint(),
                'httpMethod' => $a->getHttpMethod(),
                'country' => $a->getCountry(),
                'payload' => $a->getPayload(),
                'detectedAt' => $a->getDetectedAt()?->format(\DateTimeInterface::ATOM),
                'domain' => $a->getDomain()?->getName(),
            ], $recentAttacks),
            'leaks' => array_map(static fn (DataLeak $l) => [
                'id' => $l->getId(),
                'type' => $l->getType()?->value,
                'severity' => $l->getSeverity()->value,
                'email' => $l->getEmail(),
                'source' => $l->getSource(),
                'resolved' => $l->isResolved(),
                'detectedAt' => $l->getDetectedAt()?->format(\DateTimeInterface::ATOM),
                'domain' => $l->getDomain()?->getName(),
            ], $recentLeaks),
        ]);
    }

    private function resolveDomain(Request $request): ?\App\Entity\Domain
    {
        $apiKey = $request->headers->get('X-API-Key');
        if (!$apiKey) {
            return null;
        }

        $domain = $this->domainRepository->findOneByApiKey($apiKey);
        if ($domain === null || !$domain->isMonitoringEnabled()) {
            return null;
        }

        return $domain;
    }

    private function decodeJson(Request $request): ?array
    {
        try {
            $data = json_decode($request->getContent(), true, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }

        return is_array($data) ? $data : null;
    }

    private function field(array $payload, string $key, int $maxLength): ?string
    {
        $value = $payload[$key] ?? null;
        if (!is_string($value) && !is_int($value) && !is_float($value)) {
            return null;
        }

        $value = trim((string) $value);
        return $value === '' ? null : mb_substr($value, 0, $maxLength);
    }

    private function email(array $payload): ?string
    {
        $value = $this->field($payload, 'email', 255);
        return $value !== null && filter_var($value, FILTER_VALIDATE_EMAIL) ? $value : null;
    }

    private function ip(array $payload, string $key = 'ipAddress'): ?string
    {
        $value = $this->field($payload, $key, 45);
        return $value !== null && filter_var($value, FILTER_VALIDATE_IP) ? $value : null;
    }
}
