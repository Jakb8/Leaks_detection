<?php

namespace App\Repository;

use App\Entity\ApiFeed;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

/**
 * @extends ServiceEntityRepository<ApiFeed>
 */
class ApiFeedRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, ApiFeed::class);
    }

    public function findOneByKind(string $kind): ?ApiFeed
    {
        return $this->findOneBy(['kind' => $kind]);
    }
}
