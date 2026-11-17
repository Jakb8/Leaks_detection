<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Auto-generated Migration: Please modify to your needs!
 */
final class Version20261017152217 extends AbstractMigration
{
    public function getDescription(): string
    {
        return '';
    }

    public function up(Schema $schema): void
    {
        // this up() migration is auto-generated, please modify it to your needs
        $this->addSql('CREATE TABLE api_feed (id INT AUTO_INCREMENT NOT NULL, kind VARCHAR(20) NOT NULL, endpoint_url VARCHAR(255) NOT NULL, auth_header_name VARCHAR(120) DEFAULT NULL, auth_token VARCHAR(255) DEFAULT NULL, http_method VARCHAR(20) DEFAULT NULL, query_params VARCHAR(255) DEFAULT NULL, enabled TINYINT(1) NOT NULL, poll_interval_seconds INT NOT NULL, created_at DATETIME NOT NULL, last_synced_at DATETIME DEFAULT NULL, last_status VARCHAR(20) DEFAULT NULL, last_message VARCHAR(255) DEFAULT NULL, last_imported_count INT NOT NULL, UNIQUE INDEX UNIQ_2B732583BC4BCD9 (kind), PRIMARY KEY(id)) DEFAULT CHARACTER SET utf8mb4');
    }

    public function down(Schema $schema): void
    {
        // this down() migration is auto-generated, please modify it to your needs
        $this->addSql('DROP TABLE api_feed');
    }
}
