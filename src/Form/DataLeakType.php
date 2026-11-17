<?php

namespace App\Form;

use App\Entity\DataLeak;
use App\Entity\Domain;
use App\Enum\LeakType;
use App\Enum\Severity;
use Symfony\Bridge\Doctrine\Form\Type\EntityType;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\ChoiceType;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\TextareaType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;

class DataLeakType extends AbstractType
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
                    array_map(static fn (LeakType $t) => $t->label(), LeakType::cases()),
                    array_map(static fn (LeakType $t) => $t->value, LeakType::cases())
                ),
                'label' => 'Leak Type',
            ])
            ->add('severity', ChoiceType::class, [
                'choices' => array_combine(
                    array_map(static fn (Severity $s) => $s->label(), Severity::cases()),
                    array_map(static fn (Severity $s) => $s->value, Severity::cases())
                ),
                'label' => 'Severity',
                'data' => Severity::MEDIUM->value,
            ])
            ->add('dataSample', TextareaType::class, [
                'label' => 'Data Sample',
                'attr' => ['rows' => 4],
            ])
            ->add('source', TextType::class, [
                'label' => 'Source',
                'required' => false,
            ])
            ->add('email', EmailType::class, [
                'label' => 'Associated Email',
                'required' => false,
            ])
            ->add('ipAddress', TextType::class, [
                'label' => 'Source IP',
                'required' => false,
            ])
            ->add('country', TextType::class, [
                'label' => 'Country',
                'required' => false,
            ]);
    }

    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            'data_class' => DataLeak::class,
            'domains' => [],
        ]);
        $resolver->setAllowedTypes('domains', 'array');
    }
}
