<?php

namespace App\Command;

use App\Service\LeakScanService;
use App\Service\SettingsService;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(name: 'app:scan-leaks', description: 'Scan domains against XposedOrNot, ransomware.live, Hudson Rock and LeakRadar')]
class ScanLeaksCommand extends Command
{
    public function __construct(
        private readonly LeakScanService $leakScanService,
        private readonly SettingsService $settings,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addOption('loop', null, InputOption::VALUE_NONE, 'Run continuously using the configured scan interval');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        if ($input->getOption('loop')) {
            $interval = max(30, $this->settings->getInt(SettingsService::XON_SCAN_INTERVAL, 120));
            $io->note(sprintf('Continuous leak scan (XposedOrNot + ransomware.live + Hudson Rock + LeakRadar) every %d seconds. Ctrl+C to stop.', $interval));
            while (true) {
                $this->runScan($io);
                sleep($interval);
            }
        }

        $this->runScan($io);
        return Command::SUCCESS;
    }

    private function runScan(SymfonyStyle $io): void
    {
        if (!$this->settings->getBool(SettingsService::XON_ENABLED, false)) {
            $io->warning('Leak scanning is disabled. Enable XposedOrNot in Settings.');
            return;
        }

        [$domains, $imported] = $this->leakScanService->scanAll();
        $io->text(sprintf('[%s] Scanned %d domain(s), imported %d new breach(es).', date('H:i:s'), $domains, $imported));
    }
}
