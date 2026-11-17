<?php

namespace App\Entity;

use App\Repository\ApiFeedRepository;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: ApiFeedRepository::class)]
class ApiFeed
{
    public const KIND_ATTACK = 'attack';
    public const KIND_LEAK = 'leak';

    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(length: 20, unique: true)]
    private ?string $kind = null;

    #[ORM\Column(length: 255, nullable: true)]
    private ?string $endpointUrl = null;

    #[ORM\Column(length: 120, nullable: true)]
    private ?string $authHeaderName = null;

    #[ORM\Column(length: 255, nullable: true)]
    private ?string $authToken = null;

    #[ORM\Column(length: 20, nullable: true)]
    private ?string $httpMethod = 'GET';

    #[ORM\Column(nullable: true)]
    private ?string $queryParams = null;

    #[ORM\Column]
    private bool $enabled = false;

    #[ORM\Column]
    private ?int $pollIntervalSeconds = 10;

    #[ORM\Column]
    private ?\DateTimeImmutable $createdAt = null;

    #[ORM\Column(nullable: true)]
    private ?\DateTimeImmutable $lastSyncedAt = null;

    #[ORM\Column(length: 20, nullable: true)]
    private ?string $lastStatus = null;

    #[ORM\Column(length: 255, nullable: true)]
    private ?string $lastMessage = null;

    #[ORM\Column]
    private int $lastImportedCount = 0;

    public function __construct()
    {
        $this->createdAt = new \DateTimeImmutable();
    }

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getKind(): ?string
    {
        return $this->kind;
    }

    public function setKind(string $kind): static
    {
        $this->kind = $kind;
        return $this;
    }

    public function getEndpointUrl(): ?string
    {
        return $this->endpointUrl;
    }

    public function setEndpointUrl(?string $endpointUrl): static
    {
        $this->endpointUrl = $endpointUrl;
        return $this;
    }

    public function getAuthHeaderName(): ?string
    {
        return $this->authHeaderName;
    }

    public function setAuthHeaderName(?string $authHeaderName): static
    {
        $this->authHeaderName = $authHeaderName;
        return $this;
    }

    public function getAuthToken(): ?string
    {
        return $this->authToken;
    }

    public function setAuthToken(?string $authToken): static
    {
        $this->authToken = $authToken;
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

    public function getQueryParams(): ?string
    {
        return $this->queryParams;
    }

    public function setQueryParams(?string $queryParams): static
    {
        $this->queryParams = $queryParams;
        return $this;
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    public function setEnabled(bool $enabled): static
    {
        $this->enabled = $enabled;
        return $this;
    }

    public function getPollIntervalSeconds(): ?int
    {
        return $this->pollIntervalSeconds;
    }

    public function setPollIntervalSeconds(?int $pollIntervalSeconds): static
    {
        $this->pollIntervalSeconds = $pollIntervalSeconds;
        return $this;
    }

    public function getCreatedAt(): ?\DateTimeImmutable
    {
        return $this->createdAt;
    }

    public function setCreatedAt(\DateTimeImmutable $createdAt): static
    {
        $this->createdAt = $createdAt;
        return $this;
    }

    public function getLastSyncedAt(): ?\DateTimeImmutable
    {
        return $this->lastSyncedAt;
    }

    public function setLastSyncedAt(?\DateTimeImmutable $lastSyncedAt): static
    {
        $this->lastSyncedAt = $lastSyncedAt;
        return $this;
    }

    public function getLastStatus(): ?string
    {
        return $this->lastStatus;
    }

    public function setLastStatus(?string $lastStatus): static
    {
        $this->lastStatus = $lastStatus;
        return $this;
    }

    public function getLastMessage(): ?string
    {
        return $this->lastMessage;
    }

    public function setLastMessage(?string $lastMessage): static
    {
        $this->lastMessage = $lastMessage !== null ? mb_substr($lastMessage, 0, 255) : null;
        return $this;
    }

    public function getLastImportedCount(): int
    {
        return $this->lastImportedCount;
    }

    public function setLastImportedCount(int $lastImportedCount): static
    {
        $this->lastImportedCount = $lastImportedCount;
        return $this;
    }
}
