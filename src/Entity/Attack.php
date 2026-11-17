<?php

namespace App\Entity;

use App\Enum\AttackStatus;
use App\Enum\AttackType;
use App\Enum\Severity;
use App\Repository\AttackRepository;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: AttackRepository::class)]
class Attack
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(enumType: AttackType::class)]
    private ?AttackType $type = null;

    #[ORM\Column(enumType: Severity::class)]
    private Severity $severity = Severity::HIGH;

    #[ORM\Column(enumType: AttackStatus::class)]
    private AttackStatus $status = AttackStatus::DETECTED;

    #[ORM\Column(length: 255, nullable: true)]
    private ?string $sourceIp = null;

    #[ORM\Column(length: 255, nullable: true)]
    private ?string $endpoint = null;

    #[ORM\Column(length: 20, nullable: true)]
    private ?string $httpMethod = null;

    #[ORM\Column(length: 120, nullable: true)]
    private ?string $country = null;

    #[ORM\Column(length: 255, nullable: true)]
    private ?string $userAgent = null;

    #[ORM\Column(type: Types::TEXT, nullable: true)]
    private ?string $payload = null;

    #[ORM\Column(length: 64, nullable: true, unique: true)]
    private ?string $fingerprint = null;

    #[ORM\Column]
    private ?\DateTimeImmutable $detectedAt = null;

    #[ORM\Column(nullable: true)]
    private ?\DateTimeImmutable $resolvedAt = null;

    #[ORM\ManyToOne(inversedBy: 'attacks')]
    #[ORM\JoinColumn(nullable: false, onDelete: 'CASCADE')]
    private ?Domain $domain = null;

    public function __construct()
    {
        $this->detectedAt = new \DateTimeImmutable();
    }

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getType(): ?AttackType
    {
        return $this->type;
    }

    public function setType(AttackType $type): static
    {
        $this->type = $type;
        return $this;
    }

    public function getSeverity(): Severity
    {
        return $this->severity;
    }

    public function setSeverity(Severity $severity): static
    {
        $this->severity = $severity;
        return $this;
    }

    public function getStatus(): AttackStatus
    {
        return $this->status;
    }

    public function setStatus(AttackStatus $status): static
    {
        $this->status = $status;
        if ($status === AttackStatus::MITIGATED || $status === AttackStatus::BLOCKED) {
            $this->resolvedAt = new \DateTimeImmutable();
        }
        return $this;
    }

    public function getSourceIp(): ?string
    {
        return $this->sourceIp;
    }

    public function setSourceIp(?string $sourceIp): static
    {
        $this->sourceIp = $sourceIp;
        return $this;
    }

    public function getEndpoint(): ?string
    {
        return $this->endpoint;
    }

    public function setEndpoint(?string $endpoint): static
    {
        $this->endpoint = $endpoint;
        return $this;
    }

    public function getHttpMethod(): ?string
    {
        return $this->httpMethod;
    }

    public function setHttpMethod(?string $httpMethod): static
    {
        $this->httpMethod = $httpMethod;
        return $this;
    }

    public function getCountry(): ?string
    {
        return $this->country;
    }

    public function setCountry(?string $country): static
    {
        $this->country = $country;
        return $this;
    }

    public function getUserAgent(): ?string
    {
        return $this->userAgent;
    }

    public function setUserAgent(?string $userAgent): static
    {
        $this->userAgent = $userAgent;
        return $this;
    }

    public function getPayload(): ?string
    {
        return $this->payload;
    }

    public function setPayload(?string $payload): static
    {
        $this->payload = $payload;
        return $this;
    }

    public function getDetectedAt(): ?\DateTimeImmutable
    {
        return $this->detectedAt;
    }

    public function setDetectedAt(\DateTimeImmutable $detectedAt): static
    {
        $this->detectedAt = $detectedAt;
        return $this;
    }

    public function getResolvedAt(): ?\DateTimeImmutable
    {
        return $this->resolvedAt;
    }

    public function setResolvedAt(?\DateTimeImmutable $resolvedAt): static
    {
        $this->resolvedAt = $resolvedAt;
        return $this;
    }

    public function getDomain(): ?Domain
    {
        return $this->domain;
    }

    public function setDomain(?Domain $domain): static
    {
        $this->domain = $domain;
        return $this;
    }

    public function getFingerprint(): ?string
    {
        return $this->fingerprint;
    }

    public function setFingerprint(?string $fingerprint): static
    {
        $this->fingerprint = $fingerprint;
        return $this;
    }
}
