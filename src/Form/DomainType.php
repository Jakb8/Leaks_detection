<?php

namespace App\Form;

use App\Entity\Domain;
use App\Entity\User;
use Symfony\Bridge\Doctrine\Form\Type\EntityType;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\CheckboxType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Component\Validator\Constraints\NotBlank;
use Symfony\Component\Validator\Constraints\Regex;

class DomainType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $builder
            ->add('name', TextType::class, [
                'label' => 'Domain Name',
                'attr' => ['placeholder' => 'example.com'],
                'constraints' => [
                    new NotBlank(),
                    new Regex('/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i', message: 'Enter a valid domain name.'),
                ],
            ])
            ->add('monitoringEnabled', CheckboxType::class, [
                'label' => 'Enable monitoring',
                'required' => false,
                'data' => true,
            ]);

        if ($options['isAdmin']) {
            $builder->add('owner', EntityType::class, [
                'class' => User::class,
                'choice_label' => 'email',
                'label' => 'Owner (Client)',
                'required' => false,
            ]);
        }
    }

    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            'data_class' => Domain::class,
            'isAdmin' => false,
        ]);
        $resolver->setAllowedTypes('isAdmin', 'bool');
    }
}
