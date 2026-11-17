<?php

namespace App\Enum;

enum AttackType: string
{
    case A01_BROKEN_ACCESS = 'A01';
    case A02_CRYPTO_FAILURES = 'A02';
    case A03_INJECTION = 'A03';
    case A04_INSECURE_DESIGN = 'A04';
    case A05_MISCONFIGURATION = 'A05';
    case A06_VULNERABLE_COMPONENTS = 'A06';
    case A07_AUTH_FAILURES = 'A07';
    case A08_INTEGRITY_FAILURES = 'A08';
    case A09_LOGGING_FAILURES = 'A09';
    case A10_SSRF = 'A10';

    public function code(): string
    {
        return $this->value;
    }

    public function label(): string
    {
        return match ($this) {
            self::A01_BROKEN_ACCESS => 'A01:2021 - Broken Access Control',
            self::A02_CRYPTO_FAILURES => 'A02:2021 - Cryptographic Failures',
            self::A03_INJECTION => 'A03:2021 - Injection',
            self::A04_INSECURE_DESIGN => 'A04:2021 - Insecure Design',
            self::A05_MISCONFIGURATION => 'A05:2021 - Security Misconfiguration',
            self::A06_VULNERABLE_COMPONENTS => 'A06:2021 - Vulnerable and Outdated Components',
            self::A07_AUTH_FAILURES => 'A07:2021 - Identification and Authentication Failures',
            self::A08_INTEGRITY_FAILURES => 'A08:2021 - Software and Data Integrity Failures',
            self::A09_LOGGING_FAILURES => 'A09:2021 - Security Logging and Monitoring Failures',
            self::A10_SSRF => 'A10:2021 - Server-Side Request Forgery (SSRF)',
        };
    }
}
