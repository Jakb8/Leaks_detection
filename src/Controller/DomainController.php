<?php

namespace App\Controller;

use App\Entity\Domain;
use App\Form\DomainType;
use App\Repository\AttackRepository;
use App\Repository\DataLeakRepository;
use App\Repository\DomainRepository;
use App\Service\DomainContext;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

#[Route('/domains')]
class DomainController extends AbstractController
{
    public function __construct(
        private readonly DomainRepository $domainRepository,
        private readonly DomainContext $domainContext,
        private readonly DataLeakRepository $dataLeakRepository,
        private readonly AttackRepository $attackRepository,
    ) {
    }

    #[Route('', name: 'app_domain_index', methods: ['GET'])]
    public function index(): Response
    {
        $user = $this->domainContext->currentUser();
        $domains = $this->domainContext->accessibleDomains();

        return $this->render('domain/index.html.twig', [
            'domains' => $domains,
            'isAdmin' => $this->domainContext->isAdmin(),
            'user' => $user,
        ]);
    }

    #[Route('/new', name: 'app_domain_new', methods: ['GET', 'POST'])]
    public function new(Request $request, EntityManagerInterface $em): Response
    {
        $domain = new Domain();
        $form = $this->createForm(DomainType::class, $domain, [
            'isAdmin' => $this->domainContext->isAdmin(),
        ]);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $domain->setApiKey(bin2hex(random_bytes(16)));

            if (!$this->domainContext->isAdmin()) {
                $domain->setOwner($this->domainContext->currentUser());
            } else {
                $owner = $form->get('owner')->getData();
                $domain->setOwner($owner);
            }

            $em->persist($domain);
            $em->flush();

            $this->addFlash('success', 'Domain created successfully. Save this API key: '.$domain->getApiKey());

            return $this->redirectToRoute('app_domain_index');
        }

        return $this->render('domain/new.html.twig', [
            'form' => $form->createView(),
            'isAdmin' => $this->domainContext->isAdmin(),
        ]);
    }

    #[Route('/{id}/edit', name: 'app_domain_edit', methods: ['GET', 'POST'])]
    public function edit(Domain $domain, Request $request, EntityManagerInterface $em): Response
    {
        if (!$this->domainContext->canAccessDomain($domain)) {
            throw $this->createAccessDeniedException('You cannot access this domain.');
        }

        $form = $this->createForm(DomainType::class, $domain, [
            'isAdmin' => $this->domainContext->isAdmin(),
        ]);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            if (!$this->domainContext->isAdmin()) {
                $domain->setOwner($this->domainContext->currentUser());
            }
            $em->flush();

            $this->addFlash('success', 'Domain updated successfully.');
            return $this->redirectToRoute('app_domain_index');
        }

        return $this->render('domain/edit.html.twig', [
            'form' => $form->createView(),
            'domain' => $domain,
            'isAdmin' => $this->domainContext->isAdmin(),
        ]);
    }

    #[Route('/{id}', name: 'app_domain_delete', methods: ['POST'])]
    public function delete(Domain $domain, Request $request, EntityManagerInterface $em): Response
    {
        if (!$this->domainContext->canAccessDomain($domain)) {
            throw $this->createAccessDeniedException('You cannot access this domain.');
        }

        if (!$this->isCsrfTokenValid('delete'.$domain->getId(), $request->request->get('_token'))) {
            $this->addFlash('danger', 'Invalid security token.');
            return $this->redirectToRoute('app_domain_index');
        }

        $em->remove($domain);
        $em->flush();
        $this->addFlash('success', 'Domain deleted successfully.');

        return $this->redirectToRoute('app_domain_index');
    }

    #[Route('/{id}/show', name: 'app_domain_show', methods: ['GET'])]
    public function show(Domain $domain): Response
    {
        if (!$this->domainContext->canAccessDomain($domain)) {
            throw $this->createAccessDeniedException('You cannot access this domain.');
        }

        $leaks = $this->dataLeakRepository->findFiltered([(int) $domain->getId()], null, null);
        $attacks = $this->attackRepository->findFiltered([(int) $domain->getId()], null, null, null);

        return $this->render('domain/show.html.twig', [
            'domain' => $domain,
            'leaks' => $leaks,
            'attacks' => $attacks,
            'isAdmin' => $this->domainContext->isAdmin(),
        ]);
    }
}
