<?php

namespace App\Repository;

use App\Entity\DataLeak;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\ORM\QueryBuilder;
use Doctrine\Persistence\ManagerRegistry;
use SortDirection;

/**
 * @extends ServiceEntityRepository<DataLeak>
 */
class DataLeakRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, DataLeak::class);
    }

    /**
     * @param int[]|null $domainIds
     * @return DataLeak[]
     */
    public function findFiltered(?array $domainIds, ?string $severity, ?string $type, bool $unresolvedOnly = false, ?string $q = null): array
    {
        $qb = $this->createQueryBuilder('l')
            ->leftJoin('l.domain', 'd')
            ->addSelect('d')
            ->orderBy('l.detectedAt', SortDirection::Descending);

        $this->applyFilters($qb, $domainIds, $severity, $type, $unresolvedOnly, $q);

        return $qb->getQuery()->getResult();
    }

    /**
     * @param int[]|null $domainIds
     * @return DataLeak[]
     */
    public function findRecentLeaks(?array $domainIds, int $limit = 20, ?\DateTimeImmutable $since = null): array
    {
        $qb = $this->createQueryBuilder('l')
            ->leftJoin('l.domain', 'd')
            ->addSelect('d')
            ->orderBy('l.detectedAt', SortDirection::Descending)
            ->setMaxResults($limit);

        if ($domainIds !== null) {
            $qb->andWhere($domainIds === [] ? '1 = 0' : 'l.domain IN (:domains)');
            if ($domainIds !== []) {
                $qb->setParameter('domains', $domainIds);
            }
        }

        if ($since !== null) {
            $qb->andWhere('l.detectedAt > :since')->setParameter('since', $since);
        }

        return $qb->getQuery()->getResult();
    }

    public function countByDomain(?array $domainIds, bool $unresolvedOnly = false): int
    {
        $qb = $this->createQueryBuilder('l')
            ->select('COUNT(l.id)');

        $this->applyFilters($qb, $domainIds, null, null, $unresolvedOnly);

        return (int) $qb->getQuery()->getSingleScalarResult();
    }

    /**
     * @param int[]|null $domainIds
     * @return array<int, array{severity: string, total: int}>
     */
    public function countGroupedBySeverity(?array $domainIds): array
    {
        $qb = $this->createQueryBuilder('l')
            ->select('l.severity AS severity, COUNT(l.id) AS total')
            ->groupBy('l.severity');

        $this->applyFilters($qb, $domainIds, null, null, false);

        $rows = $qb->getQuery()->getResult();

        return array_map(static function (array $row): array {
            $sev = $row['severity'];
            return [
                'severity' => $sev instanceof \BackedEnum ? $sev->value : (string) $sev,
                'total' => (int) $row['total'],
            ];
        }, $rows);
    }

    private function applyFilters(QueryBuilder $qb, ?array $domainIds, ?string $severity, ?string $type, bool $unresolvedOnly, ?string $q = null): void
    {
        if ($domainIds !== null) {
            if ($domainIds === []) {
                $qb->andWhere('1 = 0');
                return;
            }
            $qb->andWhere('l.domain IN (:domains)')
                ->setParameter('domains', $domainIds);
        }

        if ($severity) {
            $qb->andWhere('l.severity = :severity')
                ->setParameter('severity', $severity);
        }

        if ($type) {
            $qb->andWhere('l.type = :type')
                ->setParameter('type', $type);
        }

        if ($unresolvedOnly) {
            $qb->andWhere('l.resolved = false');
        }
        if ($q) {
            $qb->andWhere('l.email LIKE :q OR l.dataSample LIKE :q OR l.source LIKE :q OR l.ipAddress LIKE :q')
                ->setParameter('q', '%'.$q.'%');
        }
    }
}
