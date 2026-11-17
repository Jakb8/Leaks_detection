<?php

namespace App\Command;

use App\Entity\ApiFeed;
use App\Repository\ApiFeedRepository;
use App\Service\FeedSyncService;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(name: 'app:sync-feeds', description: 'Poll configured external APIs and import real attacks / leaks')]
class SyncFeedsCommand extends Command
{
    public function __construct(
        private readonly FeedSyncService $feedSyncService,
        private readonly ApiFeedRepository $feedRepository,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addOption('loop', null, InputOption::VALUE_NONE, 'Run continuously, polling on each feed interval');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        if ($input->getOption('loop')) {
            $io->note('Running continuous sync loop. Press Ctrl+C to stop.');
            $warned = false;

            while (true) {
                $feeds = array_values(array_filter(
                    $this->feedRepository->findAll(),
                    static fn (ApiFeed $feed): bool => $feed->isEnabled(),
                ));

                if ($feeds === []) {
                    if (!$warned) {
                        $io->warning('No feed is enabled. Add one in Settings; checking again in 60 seconds.');
                        $warned = true;
                    }
                    sleep(60);
                    continue;
                }

                $warned = false;
                $results = [];
                $sleep = 3600;
                foreach ($feeds as $feed) {
                    $sleep = min($sleep, max(5, (int) ($feed->getPollIntervalSeconds() ?? 5)));
                    $results[$feed->getKind()] = $this->feedSyncService->sync($feed);
                }

                foreach ($results as $kind => [$count, $msg]) {
                    $io->text(sprintf('[%s] %s: %s', date('H:i:s'), $kind, $msg));
                }

                sleep($sleep);
            }
        }

        $results = $this->feedSyncService->syncAll();
        if ($results === []) {
            $io->warning('No feeds configured. Add them in Settings.');
            return Command::SUCCESS;
        }

        foreach ($results as $kind => [$count, $msg]) {
            $io->text(sprintf('%s: %s', $kind, $msg));
        }

        return Command::SUCCESS;
    }
}
