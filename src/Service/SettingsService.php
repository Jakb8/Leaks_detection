<?php

namespace App\Service;

use App\Entity\Setting;
use App\Repository\SettingRepository;
use Doctrine\ORM\EntityManagerInterface;

class SettingsService
{
    public const XON_ENABLED = 'xon_enabled';
    public const XON_API_KEY = 'xon_api_key';
    public const XON_SCAN_INTERVAL = 'xon_scan_interval';
    public const XON_SCAN_EMAILS = 'xon_scan_emails';
    public const LEAKRADAR_API_KEY = 'leakradar_api_key';
    public const TOUR_COMPLETED = 'tour_completed';

    public function __construct(
        private readonly SettingRepository $repository,
        private readonly EntityManagerInterface $em,
    ) {
    }

    /** @var array<string, string>|null */
    private ?array $values = null;

    public function get(string $key, ?string $default = null): ?string
    {
        return $this->all()[$key] ?? $default;
    }

    public function getBool(string $key, bool $default = false): bool
    {
        $value = $this->all()[$key] ?? null;
        if ($value === null) {
            return $default;
        }
        return in_array(strtolower($value), ['1', 'true', 'yes', 'on'], true);
    }

    public function getInt(string $key, int $default = 0): int
    {
        $value = $this->all()[$key] ?? null;
        return $value === null || $value === '' ? $default : (int) $value;
    }

    public function has(string $key): bool
    {
        return trim((string) ($this->all()[$key] ?? '')) !== '';
    }

    public function set(string $key, ?string $value): void
    {
        $setting = $this->repository->findOneBy(['settingKey' => $key]);
        if ($setting === null) {
            $setting = new Setting();
            $setting->setSettingKey($key);
            $this->em->persist($setting);
        }
        $setting->setSettingValue($value);
        $this->em->flush();

        if ($this->values !== null) {
            $this->values[$key] = $value ?? '';
        }
    }

    /**
     * @return array<string, string>
     */
    private function all(): array
    {
        if ($this->values === null) {
            $this->values = [];
            foreach ($this->repository->findAll() as $setting) {
                $this->values[$setting->getSettingKey()] = $setting->getSettingValue() ?? '';
            }
        }

        return $this->values;
    }
}
