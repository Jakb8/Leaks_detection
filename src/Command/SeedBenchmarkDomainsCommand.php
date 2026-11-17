<?php

namespace App\Command;

use App\Entity\Domain;
use App\Repository\DomainRepository;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(name: 'app:seed-benchmark-domains', description: 'Replace monitored domains with well-known breach benchmark domains')]
class SeedBenchmarkDomainsCommand extends Command
{
    private const DOMAINS = [
        'canva.com',
        'adobe.com',
        'dropbox.com',
        '23andme.com',
        'ticketmaster.com',
        'santander.com',
    ];

    public function __construct(
        private readonly DomainRepository $domainRepository,
        private readonly UserRepository $userRepository,
        private readonly EntityManagerInterface $em,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addOption('force', null, InputOption::VALUE_NONE, 'Confirm deletion of existing domains and their findings');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        if (!$input->getOption('force')) {
            $io->warning('This deletes all monitored domains and their attacks/leaks. Re-run with --force to continue.');
            return Command::FAILURE;
        }

        foreach ($this->domainRepository->findAll() as $domain) {
            $this->em->remove($domain);
        }
        $this->em->flush();

        $owner = $this->userRepository->findOneBy(['email' => 'admin@watchleaks.local']);
        $rows = [];

        foreach (self::DOMAINS as $name) {
            $domain = new Domain();
            $domain->setName($name)
                ->setApiKey(bin2hex(random_bytes(16)))
                ->setMonitoringEnabled(true)
                ->setOwner($owner);
            $this->em->persist($domain);

            $rows[] = [$name, substr((string) $domain->getApiKey(), 0, 8).'…', $owner?->getEmail() ?? '-'];
        }

        $this->em->flush();

        $io->success(sprintf('%d benchmark domains created.', count(self::DOMAINS)));
        $io->table(['Domain', 'API key', 'Owner'], $rows);

        return Command::SUCCESS;
    }
}
