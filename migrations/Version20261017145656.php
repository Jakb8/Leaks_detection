<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Auto-generated Migration: Please modify to your needs!
 */
final class Version20261017145656 extends AbstractMigration
{
    public function getDescription(): string
    {
        return '';
    }

    public function up(Schema $schema): void
    {
        // this up() migration is auto-generated, please modify it to your needs
        $this->addSql('CREATE TABLE attack (id INT AUTO_INCREMENT NOT NULL, type VARCHAR(255) NOT NULL, severity VARCHAR(255) NOT NULL, status VARCHAR(255) NOT NULL, source_ip VARCHAR(255) DEFAULT NULL, endpoint VARCHAR(255) DEFAULT NULL, http_method VARCHAR(20) DEFAULT NULL, country VARCHAR(120) DEFAULT NULL, user_agent VARCHAR(255) DEFAULT NULL, payload LONGTEXT DEFAULT NULL, detected_at DATETIME NOT NULL, resolved_at DATETIME DEFAULT NULL, domain_id INT NOT NULL, INDEX IDX_47C02D3B115F0EE5 (domain_id), PRIMARY KEY(id)) DEFAULT CHARACTER SET utf8mb4');
        $this->addSql('CREATE TABLE data_leak (id INT AUTO_INCREMENT NOT NULL, type VARCHAR(255) NOT NULL, severity VARCHAR(255) NOT NULL, data_sample LONGTEXT NOT NULL, source VARCHAR(255) DEFAULT NULL, email VARCHAR(255) DEFAULT NULL, ip_address VARCHAR(255) DEFAULT NULL, country VARCHAR(120) DEFAULT NULL, resolved TINYINT(1) NOT NULL, detected_at DATETIME NOT NULL, resolved_at DATETIME DEFAULT NULL, domain_id INT NOT NULL, INDEX IDX_361B7B8115F0EE5 (domain_id), PRIMARY KEY(id)) DEFAULT CHARACTER SET utf8mb4');
        $this->addSql('CREATE TABLE domain (id INT AUTO_INCREMENT NOT NULL, name VARCHAR(255) NOT NULL, api_key VARCHAR(255) DEFAULT NULL, monitoring_enabled TINYINT(1) NOT NULL, created_at DATETIME NOT NULL, last_scan_at DATETIME DEFAULT NULL, owner_id INT DEFAULT NULL, UNIQUE INDEX UNIQ_A7A91E0B5E237E06 (name), INDEX IDX_A7A91E0B7E3C61F9 (owner_id), PRIMARY KEY(id)) DEFAULT CHARACTER SET utf8mb4');
        $this->addSql('CREATE TABLE `user` (id INT AUTO_INCREMENT NOT NULL, email VARCHAR(180) NOT NULL, roles JSON NOT NULL, password VARCHAR(255) NOT NULL, full_name VARCHAR(120) DEFAULT NULL, company VARCHAR(120) DEFAULT NULL, is_active TINYINT(1) NOT NULL, created_at DATETIME NOT NULL, last_login_at DATETIME DEFAULT NULL, UNIQUE INDEX UNIQ_8D93D649E7927C74 (email), PRIMARY KEY(id)) DEFAULT CHARACTER SET utf8mb4');
        $this->addSql('CREATE TABLE messenger_messages (id BIGINT AUTO_INCREMENT NOT NULL, body LONGTEXT NOT NULL, headers LONGTEXT NOT NULL, queue_name VARCHAR(190) NOT NULL, created_at DATETIME NOT NULL, available_at DATETIME NOT NULL, delivered_at DATETIME DEFAULT NULL, INDEX IDX_75EA56E0FB7336F0E3BD61CE16BA31DBBF396750 (queue_name, available_at, delivered_at, id), PRIMARY KEY(id)) DEFAULT CHARACTER SET utf8mb4');
        $this->addSql('ALTER TABLE attack ADD CONSTRAINT FK_47C02D3B115F0EE5 FOREIGN KEY (domain_id) REFERENCES domain (id) ON DELETE CASCADE');
        $this->addSql('ALTER TABLE data_leak ADD CONSTRAINT FK_361B7B8115F0EE5 FOREIGN KEY (domain_id) REFERENCES domain (id) ON DELETE CASCADE');
        $this->addSql('ALTER TABLE domain ADD CONSTRAINT FK_A7A91E0B7E3C61F9 FOREIGN KEY (owner_id) REFERENCES `user` (id) ON DELETE SET NULL');
    }

    public function down(Schema $schema): void
    {
        // this down() migration is auto-generated, please modify it to your needs
        $this->addSql('ALTER TABLE attack DROP FOREIGN KEY FK_47C02D3B115F0EE5');
        $this->addSql('ALTER TABLE data_leak DROP FOREIGN KEY FK_361B7B8115F0EE5');
        $this->addSql('ALTER TABLE domain DROP FOREIGN KEY FK_A7A91E0B7E3C61F9');
        $this->addSql('DROP TABLE attack');
        $this->addSql('DROP TABLE data_leak');
        $this->addSql('DROP TABLE domain');
        $this->addSql('DROP TABLE `user`');
        $this->addSql('DROP TABLE messenger_messages');
    }
}
