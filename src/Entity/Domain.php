<?php

namespace App\Entity;

use App\Repository\DomainRepository;
use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Common\Collections\Collection;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Bridge\Doctrine\Validator\Constraints\UniqueEntity;

#[ORM\Entity(repositoryClass: DomainRepository::class)]
#[UniqueEntity(fields: ['name'], message: 'This domain is already registered.')]
class Domain
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(length: 255, unique: true)]
    private ?string $name = null;

    #[ORM\Column(length: 255, nullable: true)]
    private ?string $apiKey = null;

    #[ORM\Column]
    private bool $monitoringEnabled = true;

    #[ORM\Column]
    private ?\DateTimeImmutable $createdAt = null;

    #[ORM\Column(nullable: true)]
    private ?\DateTimeImmutable $lastScanAt = null;

    #[ORM\ManyToOne(inversedBy: 'domains')]
    #[ORM\JoinColumn(nullable: true, onDelete: 'SET NULL')]
    private ?User $owner = null;

    #[ORM\OneToMany(mappedBy: 'domain', targetEntity: DataLeak::class, cascade: ['remove'])]
    private Collection $dataLeaks;

    #[ORM\OneToMany(mappedBy: 'domain', targetEntity: Attack::class, cascade: ['remove'])]
    private Collection $attacks;

    public function __construct()
    {
        $this->dataLeaks = new ArrayCollection();
        $this->attacks = new ArrayCollection();
        $this->createdAt = new \DateTimeImmutable();
    }

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getName(): ?string
    {
        return $this->name;
    }

    public function setName(string $name): static
    {
        $this->name = $name;
        return $this;
    }

    public function getApiKey(): ?string
    {
        return $this->apiKey;
    }

    public function setApiKey(?string $apiKey): static
    {
        $this->apiKey = $apiKey;
        return $this;
    }

    public function isMonitoringEnabled(): bool
    {
        return $this->monitoringEnabled;
    }

    public function setMonitoringEnabled(bool $monitoringEnabled): static
    {
        $this->monitoringEnabled = $monitoringEnabled;
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

    public function getLastScanAt(): ?\DateTimeImmutable
    {
        return $this->lastScanAt;
    }

    public function setLastScanAt(?\DateTimeImmutable $lastScanAt): static
    {
        $this->lastScanAt = $lastScanAt;
        return $this;
    }

    public function getOwner(): ?User
    {
        return $this->owner;
    }

    public function setOwner(?User $owner): static
    {
        $this->owner = $owner;
        return $this;
    }

    /**
     * @return Collection<int, DataLeak>
     */
    public function getDataLeaks(): Collection
    {
        return $this->dataLeaks;
    }

    public function addDataLeak(DataLeak $dataLeak): static
    {
        if (!$this->dataLeaks->contains($dataLeak)) {
            $this->dataLeaks->add($dataLeak);
            $dataLeak->setDomain($this);
        }
        return $this;
    }

    public function removeDataLeak(DataLeak $dataLeak): static
    {
        if ($this->dataLeaks->removeElement($dataLeak)) {
            if ($dataLeak->getDomain() === $this) {
                $dataLeak->setDomain(null);
            }
        }
        return $this;
    }

    /**
     * @return Collection<int, Attack>
     */
    public function getAttacks(): Collection
    {
        return $this->attacks;
    }

    public function addAttack(Attack $attack): static
    {
        if (!$this->attacks->contains($attack)) {
            $this->attacks->add($attack);
            $attack->setDomain($this);
        }
        return $this;
    }

    public function removeAttack(Attack $attack): static
    {
        if ($this->attacks->removeElement($attack)) {
            if ($attack->getDomain() === $this) {
                $attack->setDomain(null);
            }
        }
        return $this;
    }
}
