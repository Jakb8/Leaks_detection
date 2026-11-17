<?php

namespace App\Entity;

use App\Enum\LeakType;
use App\Enum\Severity;
use App\Repository\DataLeakRepository;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: DataLeakRepository::class)]
class DataLeak
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(enumType: LeakType::class)]
    private ?LeakType $type = null;

    #[ORM\Column(enumType: Severity::class)]
    private Severity $severity = Severity::MEDIUM;

    #[ORM\Column(type: Types::TEXT)]
    private ?string $dataSample = null;

    #[ORM\Column(length: 64, nullable: true, unique: true)]
    private ?string $fingerprint = null;

    #[ORM\Column(length: 255, nullable: true)]
    private ?string $source = null;

    #[ORM\Column(length: 255, nullable: true)]
    private ?string $email = null;

    #[ORM\Column(length: 255, nullable: true)]
    private ?string $ipAddress = null;

    #[ORM\Column(length: 120, nullable: true)]
    private ?string $country = null;

    #[ORM\Column]
    private bool $resolved = false;

    #[ORM\Column]
    private ?\DateTimeImmutable $detectedAt = null;

    #[ORM\Column(nullable: true)]
    private ?\DateTimeImmutable $resolvedAt = null;

    #[ORM\ManyToOne(inversedBy: 'dataLeaks')]
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

    public function getType(): ?LeakType
    {
        return $this->type;
    }

    public function setType(LeakType $type): static
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

    public function getDataSample(): ?string
    {
        return $this->dataSample;
    }

    public function setDataSample(string $dataSample): static
    {
        $this->dataSample = $dataSample;
        return $this;
    }

    public function getSource(): ?string
    {
        return $this->source;
    }

    public function setSource(?string $source): static
    {
        $this->source = $source;
        return $this;
    }

    public function getEmail(): ?string
    {
        return $this->email;
    }

    public function setEmail(?string $email): static
    {
        $this->email = $email;
        return $this;
    }

    public function getIpAddress(): ?string
    {
        return $this->ipAddress;
    }

    public function setIpAddress(?string $ipAddress): static
    {
        $this->ipAddress = $ipAddress;
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

    public function isResolved(): bool
    {
        return $this->resolved;
    }

    public function setResolved(bool $resolved): static
    {
        $this->resolved = $resolved;
        $this->resolvedAt = $resolved ? new \DateTimeImmutable() : null;
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
