<?php

namespace App\Command;

use App\Entity\Domain;
use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

#[AsCommand(name: 'app:seed', description: 'Create the admin user and a starter client (no fake attack/leak data)')]
class SeedCommand extends Command
{
    public function __construct(
        private readonly EntityManagerInterface $em,
        private readonly UserPasswordHasherInterface $passwordHasher,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addOption('with-client', null, InputOption::VALUE_NONE, 'Also create a demo client account and domain');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        $adminEmail = 'admin@watchleaks.local';
        $admin = $this->em->getRepository(User::class)->findOneBy(['email' => $adminEmail]);
        if (!$admin) {
            $admin = new User();
            $admin->setEmail($adminEmail)
                ->setFullName('WatchLeaks Admin')
                ->setCompany('WatchLeaks')
                ->setRoles(['ROLE_ADMIN']);
            $admin->setPassword($this->passwordHasher->hashPassword($admin, 'admin123'));
            $this->em->persist($admin);
            $this->em->flush();
            $io->success('Admin user created: '.$adminEmail.' / admin123');
        } else {
            $io->note('Admin user already exists: '.$adminEmail);
        }

        if ($input->getOption('with-client')) {
            $clientEmail = 'client@watchleaks.local';
            $client = $this->em->getRepository(User::class)->findOneBy(['email' => $clientEmail]);
            if (!$client) {
                $client = new User();
                $client->setEmail($clientEmail)
                    ->setFullName('Demo Client')
                    ->setCompany('Demo Corp')
                    ->setRoles(['ROLE_CLIENT']);
                $client->setPassword($this->passwordHasher->hashPassword($client, 'client123'));
                $this->em->persist($client);
                $this->em->flush();
                $io->success('Client user created: '.$clientEmail.' / client123');
            }

            $domain = $this->em->getRepository(Domain::class)->findOneBy(['name' => 'demo-client.local']);
            if (!$domain) {
                $domain = new Domain();
                $domain->setName('demo-client.local')
                    ->setApiKey(bin2hex(random_bytes(16)))
                    ->setOwner($client)
                    ->setMonitoringEnabled(true);
                $this->em->persist($domain);
                $this->em->flush();
                $io->success('Demo domain created: demo-client.local');
            }
        }

        $io->success('Done. WatchLeaks ready — connect your real APIs in Settings.');
        return Command::SUCCESS;
    }
}
