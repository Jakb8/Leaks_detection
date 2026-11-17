<?php

namespace App\Enum;

enum LeakType: string
{
    case EMAIL = 'email';
    case PASSWORD = 'password';
    case CREDENTIALS = 'credentials';
    case DATABASE = 'database';
    case API_KEY = 'api_key';
    case PERSONAL_DATA = 'personal_data';
    case FINANCIAL = 'financial';

    public function label(): string
    {
        return match ($this) {
            self::EMAIL => 'Email Address',
            self::PASSWORD => 'Password',
            self::CREDENTIALS => 'Login Credentials',
            self::DATABASE => 'Database Dump',
            self::API_KEY => 'API Key',
            self::PERSONAL_DATA => 'Personal Data',
            self::FINANCIAL => 'Financial Data',
        };
    }
}
