<?php

namespace App\Enum;

enum AttackStatus: string
{
    case DETECTED = 'detected';
    case BLOCKED = 'blocked';
    case INVESTIGATING = 'investigating';
    case MITIGATED = 'mitigated';

    public function label(): string
    {
        return match ($this) {
            self::DETECTED => 'Detected',
            self::BLOCKED => 'Blocked',
            self::INVESTIGATING => 'Investigating',
            self::MITIGATED => 'Mitigated',
        };
    }

    public function badgeClass(): string
    {
        return match ($this) {
            self::DETECTED => 'danger',
            self::BLOCKED => 'dark',
            self::INVESTIGATING => 'warning',
            self::MITIGATED => 'success',
        };
    }
}
