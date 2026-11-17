<?php

namespace App\Controller;

use App\Enum\AttackType;
use App\Repository\AttackRepository;
use App\Repository\DataLeakRepository;
use App\Service\DomainContext;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

class DashboardController extends AbstractController
{
    public function __construct(
        private readonly DomainContext $domainContext,
        private readonly DataLeakRepository $dataLeakRepository,
        private readonly AttackRepository $attackRepository,
        private readonly \App\Service\SettingsService $settings,
    ) {
    }

    #[Route('/tour/complete', name: 'app_tour_complete', methods: ['POST'])]
    public function completeTour(Request $request): Response
    {
        if (!$this->isCsrfTokenValid('tour_complete', $request->headers->get('X-CSRF-Token'))) {
            return $this->json(['ok' => false], Response::HTTP_FORBIDDEN);
        }

        $this->settings->set(\App\Service\SettingsService::TOUR_COMPLETED, '1');

        return $this->json(['ok' => true]);
    }

    #[Route('/', name: 'app_dashboard', methods: ['GET'])]
    public function index(): Response
    {
        $domainIds = $this->domainContext->scopedDomainIds();
        $isAdmin = $this->domainContext->isAdmin();
        $domains = $this->domainContext->accessibleDomains();

        $leaksBySeverity = $this->dataLeakRepository->countGroupedBySeverity($domainIds);
        $severityTotals = ['low' => 0, 'medium' => 0, 'high' => 0, 'critical' => 0];
        foreach ($leaksBySeverity as $row) {
            $severityTotals[$row['severity']] = (int) $row['total'];
        }

        $attacksByType = $this->attackRepository->countGroupedByType($domainIds);
        $typeTotals = [];
        foreach (AttackType::cases() as $case) {
            $typeTotals[$case->value] = 0;
        }
        foreach ($attacksByType as $row) {
            $typeTotals[$row['type']] = (int) $row['total'];
        }

        $recentAttacks = $this->attackRepository->findRecent($domainIds, 10);

        $stats = [
            'totalDomains' => count($domains),
            'totalLeaks' => $this->dataLeakRepository->countByDomain($domainIds),
            'unresolvedLeaks' => $this->dataLeakRepository->countByDomain($domainIds, true),
            'totalAttacks' => $this->attackRepository->countByDomain($domainIds),
        ];

        return $this->render('dashboard/index.html.twig', [
            'stats' => $stats,
            'severityTotals' => $severityTotals,
            'typeTotals' => $typeTotals,
            'attackTypes' => AttackType::cases(),
            'recentAttacks' => $recentAttacks,
            'isAdmin' => $isAdmin,
            'showTour' => !$this->settings->getBool(\App\Service\SettingsService::TOUR_COMPLETED),
        ]);
    }
}
