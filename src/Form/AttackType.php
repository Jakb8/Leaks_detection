<?php

namespace App\Form;

use App\Entity\Attack;
use App\Entity\Domain;
use App\Enum\AttackStatus;
use App\Enum\AttackType as AttackTypeEnum;
use App\Enum\Severity;
use Symfony\Bridge\Doctrine\Form\Type\EntityType;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\ChoiceType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\Extension\Core\Type\TextareaType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;

class AttackType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $builder
            ->add('domain', EntityType::class, [
                'class' => Domain::class,
                'choices' => $options['domains'],
                'choice_label' => 'name',
                'label' => 'Domain',
            ])
            ->add('type', ChoiceType::class, [
                'choices' => array_combine(
                    array_map(static fn (AttackTypeEnum $t) => $t->label(), AttackTypeEnum::cases()),
                    array_map(static fn (AttackTypeEnum $t) => $t->value, AttackTypeEnum::cases())
                ),
                'label' => 'Attack Type (OWASP Top 10)',
            ])
            ->add('severity', ChoiceType::class, [
                'choices' => array_combine(
                    array_map(static fn (Severity $s) => $s->label(), Severity::cases()),
                    array_map(static fn (Severity $s) => $s->value, Severity::cases())
                ),
                'label' => 'Severity',
                'data' => Severity::HIGH->value,
            ])
            ->add('status', ChoiceType::class, [
                'choices' => array_combine(
                    array_map(static fn (AttackStatus $s) => $s->label(), AttackStatus::cases()),
                    array_map(static fn (AttackStatus $s) => $s->value, AttackStatus::cases())
                ),
                'label' => 'Status',
                'data' => AttackStatus::DETECTED->value,
            ])
            ->add('sourceIp', TextType::class, [
                'label' => 'Source IP',
                'required' => false,
            ])
            ->add('endpoint', TextType::class, [
                'label' => 'Endpoint',
                'required' => false,
            ])
            ->add('httpMethod', TextType::class, [
                'label' => 'HTTP Method',
                'required' => false,
            ])
            ->add('country', TextType::class, [
                'label' => 'Country',
                'required' => false,
            ])
            ->add('userAgent', TextType::class, [
                'label' => 'User Agent',
                'required' => false,
            ])
            ->add('payload', TextareaType::class, [
                'label' => 'Payload',
                'required' => false,
                'attr' => ['rows' => 3],
            ]);
    }

    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            'data_class' => Attack::class,
            'domains' => [],
        ]);
        $resolver->setAllowedTypes('domains', 'array');
    }
}
