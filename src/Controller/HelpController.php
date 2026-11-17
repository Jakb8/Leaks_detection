<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Plain-language reference for students: what each threat term means and how
 * the dashboard works.
 */
class HelpController extends AbstractController
{
    #[Route('/help', name: 'app_help', methods: ['GET'])]
    public function index(): Response
    {
        $glossary = [
            [
                'term' => 'Data breach',
                'icon' => 'bi-database-exclamation',
                'definition' => 'An incident where a company\'s stored data is stolen and later published. WatchLeaks imports these from the XposedOrNot breach database.',
            ],
            [
                'term' => 'Infostealer',
                'icon' => 'bi-bug',
                'definition' => 'Malware (RedLine, Raccoon, Lumma…) that silently runs on an infected computer and copies everything saved in the browser: logins, cookies, autofill, wallet keys.',
            ],
            [
                'term' => 'Stealer log',
                'icon' => 'bi-file-earmark-text',
                'definition' => 'The file the malware uploads after infection. It contains lines like <code>url : user : password</code>. WatchLeaks finds these on Telegram channels and dark-web forums via Hudson Rock and LeakRadar.',
            ],
            [
                'term' => 'Combolist',
                'icon' => 'bi-list-columns',
                'definition' => 'A large <code>email:password</code> list stitched together from many smaller leaks. Quality varies — many entries are outdated or reused passwords.',
            ],
            [
                'term' => 'Ransomware leak site',
                'icon' => 'bi-exclamation-octagon',
                'definition' => 'A dark-web page where a ransomware group publishes stolen files from victims who refuse to pay. WatchLeaks tracks these in real time via ransomware.live.',
            ],
            [
                'term' => 'Credentials',
                'icon' => 'bi-key',
                'definition' => 'A username/email paired with its password. The most dangerous type of leak, because password reuse lets one leaked login open other accounts.',
            ],
            [
                'term' => 'Third-party exposure',
                'icon' => 'bi-diagram-3',
                'definition' => 'Credentials belonging to a partner, supplier or customer — not your own staff. Often overlooked, but a common way attackers reach a company (supply-chain attack).',
            ],
            [
                'term' => 'Masked credentials',
                'icon' => 'bi-eye-slash',
                'definition' => 'Free threat-intelligence APIs hide the middle of a password (<code>S****9</code>) to prevent misuse. Only the full value holders (the vendor) can show it unmasked.',
            ],
        ];

        $severities = [
            ['level' => 'Low', 'class' => 'low', 'badge' => 'success', 'meaning' => 'Minor exposure — old, low-volume, or non-sensitive data.'],
            ['level' => 'Medium', 'class' => 'medium', 'badge' => 'info', 'meaning' => 'Some real exposure, but limited scope or weak impact if abused.'],
            ['level' => 'High', 'class' => 'high', 'badge' => 'warning', 'meaning' => 'Serious exposure — many accounts or useful data for phishing.'],
            ['level' => 'Critical', 'class' => 'critical', 'badge' => 'danger', 'meaning' => 'Immediate risk — employee credentials, ransomware victim, or large plaintext dump.'],
        ];

        return $this->render('help/index.html.twig', [
            'glossary' => $glossary,
            'severities' => $severities,
        ]);
    }
}
