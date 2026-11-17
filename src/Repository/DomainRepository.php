<?php

namespace App\Repository;

use App\Entity\Domain;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;
use SortDirection;

/**
 * @extends ServiceEntityRepository<Domain>
 */
class DomainRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, Domain::class);
    }

    /**
     * @return Domain[]
     */
    public function findForUser(?int $userId, bool $isAdmin): array
    {
        $qb = $this->createQueryBuilder('d')
            ->leftJoin('d.owner', 'o')
            ->addSelect('o')
            ->orderBy('d.name', SortDirection::Ascending);

        if (!$isAdmin && $userId !== null) {
            $qb->andWhere('d.owner = :owner')
                ->setParameter('owner', $userId);
        }

        return $qb->getQuery()->getResult();
    }

    public function findOneByApiKey(string $apiKey): ?Domain
    {
        return $this->findOneBy(['apiKey' => $apiKey]);
    }
}
