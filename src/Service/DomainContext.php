<?php

namespace App\Service;

use App\Entity\Domain;
use App\Entity\User;
use App\Repository\DomainRepository;
use Symfony\Bundle\SecurityBundle\Security;

class DomainContext
{
    private ?bool $admin = null;

    /** @var Domain[]|null */
    private ?array $domains = null;

    /** @var int[]|null */
    private ?array $domainIds = null;

    public function __construct(
        private readonly Security $security,
        private readonly DomainRepository $domainRepository,
    ) {
    }

    public function currentUser(): ?User
    {
        $user = $this->security->getUser();
        return $user instanceof User ? $user : null;
    }

    public function isAdmin(): bool
    {
        return $this->admin ??= $this->security->isGranted('ROLE_ADMIN');
    }

    /**
     * @return Domain[]
     */
    public function accessibleDomains(): array
    {
        if ($this->domains === null) {
            $user = $this->currentUser();
            $this->domains = $this->domainRepository->findForUser($user?->getId(), $this->isAdmin());
        }

        return $this->domains;
    }

    /**
     * Returns null for admin (means "all domains"), or an array of domain IDs for a client.
     *
     * @return int[]|null
     */
    public function scopedDomainIds(): ?array
    {
        if ($this->isAdmin()) {
            return null;
        }

        return $this->domainIds ??= array_map(
            static fn (Domain $d): int => (int) $d->getId(),
            $this->accessibleDomains()
        );
    }

    public function canAccessDomain(Domain $domain): bool
    {
        if ($this->isAdmin()) {
            return true;
        }

        return $domain->getOwner() === $this->currentUser();
    }
}
