<?php

namespace App\Form;

use App\Entity\ApiFeed;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\CheckboxType;
use Symfony\Component\Form\Extension\Core\Type\ChoiceType;
use Symfony\Component\Form\Extension\Core\Type\IntegerType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Component\Validator\Constraints\Callback;
use Symfony\Component\Validator\Constraints\NotBlank;
use Symfony\Component\Validator\Constraints\Range;
use Symfony\Component\Validator\Constraints\Url;
use Symfony\Component\Validator\Context\ExecutionContextInterface;

class ApiFeedType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $builder
            ->add('endpointUrl', TextType::class, [
                'label' => 'API Endpoint URL',
                'attr' => ['placeholder' => 'https://your-api.example.com/attacks/realtime'],
                'constraints' => [new NotBlank(), new Url(protocols: ['http', 'https'])],
            ])
            ->add('httpMethod', ChoiceType::class, [
                'label' => 'HTTP Method',
                'choices' => ['GET' => 'GET', 'POST' => 'POST'],
                'empty_data' => 'GET',
            ])
            ->add('authHeaderName', TextType::class, [
                'label' => 'Auth Header Name',
                'required' => false,
                'attr' => ['placeholder' => 'X-API-Key or Authorization'],
            ])
            ->add('authToken', PasswordType::class, [
                'label' => 'API Token / Key',
                'required' => false,
                'attr' => ['autocomplete' => 'new-password'],
            ])
            ->add('queryParams', TextType::class, [
                'label' => 'Query Parameters (optional)',
                'required' => false,
                'attr' => ['placeholder' => 'since=5m&limit=100'],
            ])
            ->add('pollIntervalSeconds', IntegerType::class, [
                'label' => 'Poll Interval (seconds)',
                'attr' => ['min' => 5, 'max' => 3600],
                'constraints' => [new Range(min: 5, max: 3600)],
            ])
            ->add('enabled', CheckboxType::class, [
                'label' => 'Enabled',
                'required' => false,
            ]);
    }

    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            'data_class' => ApiFeed::class,
            'kind_label' => '',
            'constraints' => [new Callback([self::class, 'validateEndpoint'])],
        ]);
        $resolver->setAllowedTypes('kind_label', 'string');
    }

    public static function validateEndpoint(ApiFeed $feed, ExecutionContextInterface $context): void
    {
        $host = parse_url($feed->getEndpointUrl() ?? '', PHP_URL_HOST);
        if (!is_string($host) || $host === '') {
            return;
        }

        $host = strtolower($host);
        if ($host === 'localhost' || str_ends_with($host, '.localhost') || $host === '127.0.0.1' || $host === '::1') {
            $context->buildViolation('Local addresses are not allowed as API endpoints.')
                ->atPath('endpointUrl')
                ->addViolation();
            return;
        }

        if (filter_var($host, FILTER_VALIDATE_IP) && !filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            $context->buildViolation('Private IP addresses are not allowed as API endpoints.')
                ->atPath('endpointUrl')
                ->addViolation();
        }
    }
}
