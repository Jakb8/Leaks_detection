<?php

namespace App\Repository;

use App\Entity\Attack;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\ORM\QueryBuilder;
use Doctrine\Persistence\ManagerRegistry;
use SortDirection;

/**
 * @extends ServiceEntityRepository<Attack>
 */
class AttackRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, Attack::class);
    }

    /**
     * @param int[]|null $domainIds
     * @return Attack[]
     */
    public function findFiltered(?array $domainIds, ?string $type, ?string $severity, ?string $status, ?string $q = null): array
    {
        $qb = $this->createQueryBuilder('a')
            ->leftJoin('a.domain', 'd')
            ->addSelect('d')
            ->orderBy('a.detectedAt', SortDirection::Descending);

        $this->applyFilters($qb, $domainIds, $type, $severity, $status, $q);

        return $qb->getQuery()->getResult();
    }

    /**
     * @param int[]|null $domainIds
     * @return Attack[]
     */
    public function findRecent(?array $domainIds, int $limit = 10, ?\DateTimeImmutable $since = null): array
    {
        $qb = $this->createQueryBuilder('a')
            ->leftJoin('a.domain', 'd')
            ->addSelect('d')
            ->orderBy('a.detectedAt', SortDirection::Descending)
            ->setMaxResults($limit);

        if ($since !== null) {
            $qb->andWhere('a.detectedAt > :since')->setParameter('since', $since);
        }

        $this->applyFilters($qb, $domainIds, null, null, null);

        return $qb->getQuery()->getResult();
    }

    public function countByDomain(?array $domainIds): int
    {
        $qb = $this->createQueryBuilder('a')->select('COUNT(a.id)');
        $this->applyFilters($qb, $domainIds, null, null, null);
        return (int) $qb->getQuery()->getSingleScalarResult();
    }

    /**
     * @param int[]|null $domainIds
     * @return array<int, array{type: string, total: int}>
     */
    public function countGroupedByType(?array $domainIds): array
    {
        $qb = $this->createQueryBuilder('a')
            ->select('a.type AS type, COUNT(a.id) AS total')
            ->groupBy('a.type')
            ->orderBy('total', SortDirection::Descending);

        $this->applyFilters($qb, $domainIds, null, null, null);

        $rows = $qb->getQuery()->getResult();

        return array_map(static function (array $row): array {
            $type = $row['type'];
            return [
                'type' => $type instanceof \BackedEnum ? $type->value : (string) $type,
                'total' => (int) $row['total'],
            ];
        }, $rows);
    }

    private function applyFilters(QueryBuilder $qb, ?array $domainIds, ?string $type, ?string $severity, ?string $status, ?string $q = null): void
    {
        if ($domainIds !== null) {
            if ($domainIds === []) {
                $qb->andWhere('1 = 0');
                return;
            }
            $qb->andWhere('a.domain IN (:domains)')
                ->setParameter('domains', $domainIds);
        }

        if ($type) {
            $qb->andWhere('a.type = :type')->setParameter('type', $type);
        }
        if ($severity) {
            $qb->andWhere('a.severity = :severity')->setParameter('severity', $severity);
        }
        if ($status) {
            $qb->andWhere('a.status = :status')->setParameter('status', $status);
        }
        if ($q) {
            $qb->andWhere('a.endpoint LIKE :q OR a.sourceIp LIKE :q OR a.payload LIKE :q OR a.userAgent LIKE :q')
                ->setParameter('q', '%'.$q.'%');
        }
    }
}
