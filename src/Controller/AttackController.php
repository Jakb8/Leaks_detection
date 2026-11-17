<?php

namespace App\Controller;

use App\Entity\Attack;
use App\Enum\AttackStatus;
use App\Enum\AttackType;
use App\Enum\Severity;
use App\Form\AttackType as AttackTypeForm;
use App\Repository\AttackRepository;
use App\Service\CsvExporter;
use App\Service\DomainContext;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

#[Route('/attacks')]
class AttackController extends AbstractController
{
    public function __construct(
        private readonly AttackRepository $attackRepository,
        private readonly DomainContext $domainContext,
        private readonly CsvExporter $csvExporter,
    ) {
    }

    #[Route('', name: 'app_attack_index', methods: ['GET'])]
    public function index(Request $request): Response
    {
        $domainIds = $this->domainContext->scopedDomainIds();
        $type = $request->query->get('type');
        $severity = $request->query->get('severity');
        $status = $request->query->get('status');
        $q = trim((string) $request->query->get('q', ''));

        $attacks = $this->attackRepository->findFiltered($domainIds, $type, $severity, $status, $q !== '' ? $q : null);

        if ($request->query->get('export') === 'csv') {
            return $this->csvExporter->export(
                ['Detected', 'Domain', 'Type', 'Severity', 'Source IP', 'Endpoint', 'Method', 'Country', 'Status'],
                array_map(static fn (Attack $a): array => [
                    $a->getDetectedAt()?->format('Y-m-d H:i:s'),
                    $a->getDomain()?->getName(),
                    $a->getType()?->label(),
                    $a->getSeverity()->label(),
                    $a->getSourceIp(),
                    $a->getEndpoint(),
                    $a->getHttpMethod(),
                    $a->getCountry(),
                    $a->getStatus()->label(),
                ], $attacks),
                'watchleaks-attacks-'.date('Y-m-d').'.csv'
            );
        }

        return $this->render('attack/index.html.twig', [
            'attacks' => $attacks,
            'isAdmin' => $this->domainContext->isAdmin(),
            'type' => $type,
            'severity' => $severity,
            'status' => $status,
            'q' => $q,
            'types' => AttackType::cases(),
            'severities' => Severity::cases(),
            'statuses' => AttackStatus::cases(),
        ]);
    }

    #[Route('/new', name: 'app_attack_new', methods: ['GET', 'POST'])]
    public function new(Request $request, EntityManagerInterface $em): Response
    {
        $attack = new Attack();
        $form = $this->createForm(AttackTypeForm::class, $attack, [
            'domains' => $this->domainContext->accessibleDomains(),
        ]);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            if (!$this->domainContext->canAccessDomain($attack->getDomain())) {
                throw $this->createAccessDeniedException();
            }

            $em->persist($attack);
            $em->flush();

            $this->addFlash('success', 'Attack event recorded.');
            return $this->redirectToRoute('app_attack_index');
        }

        return $this->render('attack/new.html.twig', [
            'form' => $form->createView(),
        ]);
    }

    #[Route('/{id}/status', name: 'app_attack_status', methods: ['POST'])]
    public function updateStatus(Attack $attack, Request $request, EntityManagerInterface $em): Response
    {
        if (!$this->domainContext->canAccessDomain($attack->getDomain())) {
            throw $this->createAccessDeniedException();
        }

        if (!$this->isCsrfTokenValid('status'.$attack->getId(), $request->request->get('_token'))) {
            $this->addFlash('danger', 'Invalid security token.');
            return $this->redirectToRoute('app_attack_index');
        }

        $case = AttackStatus::tryFrom((string) $request->request->get('status'));
        if ($case === null) {
            $this->addFlash('danger', 'Unknown status.');
            return $this->redirectToRoute('app_attack_index');
        }

        $attack->setStatus($case);
        $em->flush();
        $this->addFlash('success', 'Attack status updated.');

        return $this->redirectToRoute('app_attack_index');
    }

    #[Route('/{id}', name: 'app_attack_delete', methods: ['POST'])]
    public function delete(Attack $attack, Request $request, EntityManagerInterface $em): Response
    {
        if (!$this->domainContext->canAccessDomain($attack->getDomain())) {
            throw $this->createAccessDeniedException();
        }

        if (!$this->isCsrfTokenValid('delete'.$attack->getId(), $request->request->get('_token'))) {
            $this->addFlash('danger', 'Invalid security token.');
            return $this->redirectToRoute('app_attack_index');
        }

        $em->remove($attack);
        $em->flush();
        $this->addFlash('success', 'Attack event deleted.');

        return $this->redirectToRoute('app_attack_index');
    }
}
