<?php

namespace App\Controller;

use App\Repository\DomainRepository;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

#[Route('/audit')]
class AuditController extends AbstractController
{
    #[Route('', name: 'app_audit', methods: ['GET'])]
    public function index(Request $request, DomainRepository $domainRepository): Response
    {
        $this->denyAccessUnlessGranted('ROLE_ADMIN');

        $raw = trim((string) $request->query->get('domain', ''));
        $domain = $this->normalizeDomain($raw);
        $queries = [];

        if ($domain !== null) {
            $label = strstr($domain, '.', true) ?: $domain;
            $dorks = [
                'Telegram — domain exact' => sprintf('site:t.me "%s"', $domain),
                'Telegram — emails du domaine' => sprintf('site:t.me "@%s"', $domain),
                'Telegram — societe + leak' => sprintf('site:t.me "%s" leak OR database OR combo', $label),
                'Pastebin — emails du domaine' => sprintf('site:pastebin.com "@%s"', $domain),
                'Paste sites — emails du domaine' => sprintf('("@%s" OR "%s") (site:rentry.co OR site:controlc.com OR site:ghostbin.com OR site:justpaste.it)', $domain, $domain),
                'Fichiers texte — emails du domaine' => sprintf('filetype:txt "@%s"', $domain),
                'SQL — dumps mentions du domaine' => sprintf('filetype:sql "%s" "INSERT INTO"', $domain),
            ];

            foreach ($dorks as $name => $dork) {
                $queries[] = [
                    'name' => $name,
                    'value' => $dork,
                    'url' => 'https://www.google.com/search?q='.rawurlencode($dork),
                ];
            }
        }

        return $this->render('audit/index.html.twig', [
            'domains' => $domainRepository->findBy([], ['name' => 'ASC']),
            'domain' => $domain,
            'raw_domain' => $raw,
            'queries' => $queries,
        ]);
    }

    private function normalizeDomain(string $value): ?string
    {
        $value = strtolower($value);
        $value = preg_replace('#^https?://#i', '', $value) ?? '';
        $value = preg_replace('#^www\.#i', '', $value) ?? '';
        $value = rtrim($value, "/ \t\n\r\0\x0B");

        return preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/', $value)
            ? $value
            : null;
    }
}
