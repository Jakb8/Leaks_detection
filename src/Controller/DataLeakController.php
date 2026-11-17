<?php

namespace App\Controller;

use App\Entity\DataLeak;
use App\Enum\LeakType;
use App\Enum\Severity;
use App\Form\DataLeakType;
use App\Repository\DataLeakRepository;
use App\Service\CsvExporter;
use App\Service\DomainContext;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

#[Route('/leaks')]
class DataLeakController extends AbstractController
{
    public function __construct(
        private readonly DataLeakRepository $dataLeakRepository,
        private readonly DomainContext $domainContext,
        private readonly CsvExporter $csvExporter,
    ) {
    }

    #[Route('', name: 'app_leak_index', methods: ['GET'])]
    public function index(Request $request): Response
    {
        $domainIds = $this->domainContext->scopedDomainIds();
        $severity = $request->query->get('severity');
        $type = $request->query->get('type');
        $q = trim((string) $request->query->get('q', ''));
        $unresolved = $request->query->get('unresolved') === '1';

        $leaks = $this->dataLeakRepository->findFiltered($domainIds, $severity, $type, $unresolved, $q !== '' ? $q : null);

        if ($request->query->get('export') === 'csv') {
            return $this->csvExporter->export(
                ['Detected', 'Domain', 'Type', 'Severity', 'Data Sample', 'Email', 'IP', 'Source', 'Country', 'Resolved'],
                array_map(static fn (DataLeak $l): array => [
                    $l->getDetectedAt()?->format('Y-m-d H:i:s'),
                    $l->getDomain()?->getName(),
                    $l->getType()->label(),
                    $l->getSeverity()->label(),
                    $l->getDataSample(),
                    $l->getEmail(),
                    $l->getIpAddress(),
                    $l->getSource(),
                    $l->getCountry(),
                    $l->isResolved(),
                ], $leaks),
                'watchleaks-leaks-'.date('Y-m-d').'.csv'
            );
        }

        return $this->render('leak/index.html.twig', [
            'leaks' => $leaks,
            'isAdmin' => $this->domainContext->isAdmin(),
            'severity' => $severity,
            'type' => $type,
            'q' => $q,
            'unresolved' => $unresolved,
            'types' => LeakType::cases(),
            'severities' => Severity::cases(),
        ]);
    }

    #[Route('/new', name: 'app_leak_new', methods: ['GET', 'POST'])]
    public function new(Request $request, EntityManagerInterface $em): Response
    {
        $leak = new DataLeak();
        $form = $this->createForm(DataLeakType::class, $leak, [
            'domains' => $this->domainContext->accessibleDomains(),
        ]);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            if (!$this->domainContext->canAccessDomain($leak->getDomain())) {
                throw $this->createAccessDeniedException();
            }

            $em->persist($leak);
            $em->flush();

            $this->addFlash('success', 'Data leak recorded.');
            return $this->redirectToRoute('app_leak_index');
        }

        return $this->render('leak/new.html.twig', [
            'form' => $form->createView(),
        ]);
    }

    #[Route('/{id}/resolve', name: 'app_leak_resolve', methods: ['POST'])]
    public function resolve(DataLeak $leak, Request $request, EntityManagerInterface $em): Response
    {
        if (!$this->domainContext->canAccessDomain($leak->getDomain())) {
            throw $this->createAccessDeniedException();
        }

        if (!$this->isCsrfTokenValid('resolve'.$leak->getId(), $request->request->get('_token'))) {
            $this->addFlash('danger', 'Invalid security token.');
            return $this->redirectToRoute('app_leak_index');
        }

        $leak->setResolved(true);
        $em->flush();

        $this->addFlash('success', 'Leak marked as resolved.');
        return $this->redirectToRoute('app_leak_index');
    }

    #[Route('/{id}', name: 'app_leak_delete', methods: ['POST'])]
    public function delete(DataLeak $leak, Request $request, EntityManagerInterface $em): Response
    {
        if (!$this->domainContext->canAccessDomain($leak->getDomain())) {
            throw $this->createAccessDeniedException();
        }

        if (!$this->isCsrfTokenValid('delete'.$leak->getId(), $request->request->get('_token'))) {
            $this->addFlash('danger', 'Invalid security token.');
            return $this->redirectToRoute('app_leak_index');
        }

        $em->remove($leak);
        $em->flush();
        $this->addFlash('success', 'Leak deleted.');

        return $this->redirectToRoute('app_leak_index');
    }
}
