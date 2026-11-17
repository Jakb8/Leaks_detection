<?php

namespace App\Controller;

use App\Entity\ApiFeed;
use App\Form\ApiFeedType;
use App\Repository\ApiFeedRepository;
use App\Service\FeedSyncService;
use App\Service\LeakScanService;
use App\Service\SettingsService;
use App\Service\XposedOrNotClient;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

#[Route('/settings')]
class SettingsController extends AbstractController
{
    public function __construct(
        private readonly ApiFeedRepository $feedRepository,
        private readonly FeedSyncService $feedSyncService,
        private readonly SettingsService $settings,
        private readonly XposedOrNotClient $xon,
        private readonly LeakScanService $leakScanService,
    ) {
    }

    #[Route('', name: 'app_settings', methods: ['GET', 'POST'])]
    public function index(Request $request, EntityManagerInterface $em): Response
    {
        $this->denyAccessUnlessGranted('ROLE_ADMIN');

        $attackFeed = $this->getOrCreate(ApiFeed::KIND_ATTACK, $em);
        $previousToken = $attackFeed->getAuthToken();
        $attackForm = $this->createForm(ApiFeedType::class, $attackFeed);
        $attackForm->handleRequest($request);

        if ($attackForm->isSubmitted() && $attackForm->isValid()) {
            if (($attackFeed->getAuthToken() ?? '') === '') {
                $attackFeed->setAuthToken($previousToken);
            }
            $em->flush();
            $this->addFlash('success', 'Attacks API configuration saved.');
            return $this->redirectToRoute('app_settings');
        }

        // Leak-source scanning (free public endpoints; no API keys required)
        if ($request->isMethod('POST') && $request->request->has('xon_save')) {
            if ($this->isCsrfTokenValid('xon_config', $request->request->get('_token'))) {
                $this->settings->set(SettingsService::XON_ENABLED, $request->request->get('xon_enabled') ? '1' : '0');
                $this->settings->set(SettingsService::XON_SCAN_INTERVAL, (string) max(30, (int) $request->request->get('xon_scan_interval', 120)));
                $this->addFlash('success', 'Leak scanning settings saved.');
            }
            return $this->redirectToRoute('app_settings');
        }

        if ($request->isMethod('POST') && $request->request->has('api_keys_save')) {
            if ($this->isCsrfTokenValid('api_keys_config', $request->request->get('_token'))) {
                $this->saveApiKey($request, SettingsService::XON_API_KEY, 'xon_api_key', 'xon_api_key_clear');
                $this->saveApiKey($request, SettingsService::LEAKRADAR_API_KEY, 'leakradar_api_key', 'leakradar_api_key_clear');
                $this->addFlash('success', 'API keys saved.');
            } else {
                $this->addFlash('danger', 'Invalid security token.');
            }
            return $this->redirectToRoute('app_settings');
        }

        return $this->render('settings/index.html.twig', [
            'attack_form' => $attackForm->createView(),
            'attack_feed' => $attackFeed,
            'xon_enabled' => $this->settings->getBool(SettingsService::XON_ENABLED, false),
            'xon_scan_interval' => $this->settings->getInt(SettingsService::XON_SCAN_INTERVAL, 120),
            'xon_api_key_set' => $this->settings->has(SettingsService::XON_API_KEY),
            'leakradar_api_key_set' => $this->settings->has(SettingsService::LEAKRADAR_API_KEY),
        ]);
    }

    #[Route('/sync', name: 'app_settings_sync', methods: ['POST'])]
    public function syncNow(Request $request): Response
    {
        $this->denyAccessUnlessGranted('ROLE_ADMIN');

        if (!$this->isCsrfTokenValid('sync_feeds', $request->request->get('_token'))) {
            throw $this->createAccessDeniedException('Invalid CSRF token.');
        }

        foreach ($this->feedSyncService->syncAll() as $kind => [$count, $msg]) {
            $this->addFlash('success', ucfirst($kind).': '.$msg);
        }

        if ($this->settings->getBool(SettingsService::XON_ENABLED, false)) {
            [$domains, $imported] = $this->leakScanService->scanAll();
            $this->addFlash('success', sprintf('XposedOrNot: scanned %d domain(s), imported %d new breach(es).', $domains, $imported));
        }

        return $this->redirectToRoute('app_settings');
    }

    #[Route('/email-check', name: 'app_settings_email_check', methods: ['POST'])]
    public function emailCheck(Request $request): Response
    {
        $this->denyAccessUnlessGranted('ROLE_ADMIN');

        if (!$this->isCsrfTokenValid('email_check', $request->request->get('_token'))) {
            $this->addFlash('danger', 'Invalid security token.');
            return $this->redirectToRoute('app_settings');
        }

        $email = trim((string) $request->request->get('email', ''));
        if ($email !== '' && filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $result = $this->xon->checkEmail($email);
            if ($result['breached']) {
                $this->addFlash('warning', sprintf('%s found in %d breach(es): %s', $email, count($result['breaches']), implode(', ', array_slice($result['breaches'], 0, 12))));
            } else {
                $this->addFlash('success', sprintf('%s was not found in any known breach.', $email));
            }
        } else {
            $this->addFlash('danger', 'Please enter a valid email address.');
        }

        return $this->redirectToRoute('app_settings');
    }

    private function saveApiKey(Request $request, string $settingKey, string $field, string $clearField): void
    {
        if ($request->request->get($clearField)) {
            $this->settings->set($settingKey, null);
            return;
        }

        $value = trim((string) $request->request->get($field, ''));
        if ($value !== '') {
            $this->settings->set($settingKey, $value);
        }
    }

    private function getOrCreate(string $kind, EntityManagerInterface $em): ApiFeed
    {
        $feed = $this->feedRepository->findOneByKind($kind);
        if ($feed === null) {
            $feed = new ApiFeed();
            $feed->setKind($kind)->setHttpMethod('GET')->setEnabled(false)->setPollIntervalSeconds(10);
            $em->persist($feed);
            $em->flush();
        }
        return $feed;
    }
}
