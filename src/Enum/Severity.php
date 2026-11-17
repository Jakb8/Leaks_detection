<?php

namespace App\Enum;

enum Severity: string
{
    case LOW = 'low';
    case MEDIUM = 'medium';
    case HIGH = 'high';
    case CRITICAL = 'critical';

    public function label(): string
    {
        return match ($this) {
            self::LOW => 'Low',
            self::MEDIUM => 'Medium',
            self::HIGH => 'High',
            self::CRITICAL => 'Critical',
        };
    }

    public function badgeClass(): string
    {
        return match ($this) {
            self::LOW => 'success',
            self::MEDIUM => 'info',
            self::HIGH => 'warning',
            self::CRITICAL => 'danger',
        };
    }
}
