<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Auto-generated Migration: Please modify to your needs!
 */
final class Version20261017152748 extends AbstractMigration
{
    public function getDescription(): string
    {
        return '';
    }

    public function up(Schema $schema): void
    {
        // this up() migration is auto-generated, please modify it to your needs
        $this->addSql('ALTER TABLE attack ADD fingerprint VARCHAR(64) DEFAULT NULL');
        $this->addSql('CREATE UNIQUE INDEX UNIQ_47C02D3BFC0B754A ON attack (fingerprint)');
        $this->addSql('ALTER TABLE data_leak ADD fingerprint VARCHAR(64) DEFAULT NULL');
        $this->addSql('CREATE UNIQUE INDEX UNIQ_361B7B8FC0B754A ON data_leak (fingerprint)');
    }

    public function down(Schema $schema): void
    {
        // this down() migration is auto-generated, please modify it to your needs
        $this->addSql('DROP INDEX UNIQ_361B7B8FC0B754A ON data_leak');
        $this->addSql('ALTER TABLE data_leak DROP fingerprint');
        $this->addSql('DROP INDEX UNIQ_47C02D3BFC0B754A ON attack');
        $this->addSql('ALTER TABLE attack DROP fingerprint');
    }
}
