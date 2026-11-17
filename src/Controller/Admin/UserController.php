<?php

namespace App\Controller\Admin;

use App\Entity\User;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;

#[Route('/admin/users')]
class UserController extends AbstractController
{
    public function __construct(
        private readonly UserRepository $users,
        private readonly EntityManagerInterface $em,
        private readonly UserPasswordHasherInterface $hasher,
    ) {
    }

    #[Route('', name: 'app_admin_user_index', methods: ['GET'])]
    public function index(): Response
    {
        $this->denyAccessUnlessGranted('ROLE_ADMIN');

        return $this->render('admin/user/index.html.twig', [
            'users' => $this->users->findAll(),
        ]);
    }

    #[Route('/new', name: 'app_admin_user_new', methods: ['GET', 'POST'])]
    public function new(Request $request): Response
    {
        $this->denyAccessUnlessGranted('ROLE_ADMIN');

        $user = new User();
        $error = null;

        if ($request->isMethod('POST')) {
            if (!$this->isCsrfTokenValid('user_form', $request->request->get('_token'))) {
                throw $this->createAccessDeniedException('Invalid CSRF token.');
            }

            $email = trim((string) $request->request->get('email', ''));
            $password = (string) $request->request->get('password', '');

            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $error = 'Please enter a valid email address.';
            } elseif ($this->users->findOneBy(['email' => $email]) !== null) {
                $error = 'That email address is already in use.';
            } elseif (strlen($password) < 6) {
                $error = 'Password must be at least 6 characters.';
            }

            if ($error === null) {
                $user->setEmail($email);
                $user->setFullName(trim((string) $request->request->get('fullName', '')) ?: null);
                $user->setCompany(trim((string) $request->request->get('company', '')) ?: null);
                $user->setRoles([$request->request->get('role') === 'ROLE_ADMIN' ? 'ROLE_ADMIN' : 'ROLE_CLIENT']);
                $user->setIsActive($request->request->get('isActive') ? true : false);
                $user->setPassword($this->hasher->hashPassword($user, $password));

                $this->em->persist($user);
                $this->em->flush();

                $this->addFlash('success', sprintf('User %s created.', $email));

                return $this->redirectToRoute('app_admin_user_index');
            }
        }

        return $this->render('admin/user/new.html.twig', [
            'error' => $error,
            'email' => $request->request->get('email', ''),
            'fullName' => $request->request->get('fullName', ''),
            'company' => $request->request->get('company', ''),
            'role' => $request->request->get('role', 'ROLE_CLIENT'),
            'isActive' => $request->request->get('isActive') !== null,
        ]);
    }

    #[Route('/{id}/edit', name: 'app_admin_user_edit', methods: ['GET', 'POST'], requirements: ['id' => '\d+'])]
    public function edit(User $user, Request $request): Response
    {
        $this->denyAccessUnlessGranted('ROLE_ADMIN');

        $error = null;

        if ($request->isMethod('POST')) {
            if (!$this->isCsrfTokenValid('user_form', $request->request->get('_token'))) {
                throw $this->createAccessDeniedException('Invalid CSRF token.');
            }

            $email = trim((string) $request->request->get('email', ''));
            $password = (string) $request->request->get('password', '');
            $existing = $this->users->findOneBy(['email' => $email]);

            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $error = 'Please enter a valid email address.';
            } elseif ($existing !== null && $existing->getId() !== $user->getId()) {
                $error = 'That email address is already in use.';
            } elseif ($password !== '' && strlen($password) < 6) {
                $error = 'Password must be at least 6 characters.';
            }

            if ($error === null) {
                $user->setEmail($email);
                $user->setFullName(trim((string) $request->request->get('fullName', '')) ?: null);
                $user->setCompany(trim((string) $request->request->get('company', '')) ?: null);
                $user->setRoles([$request->request->get('role') === 'ROLE_ADMIN' ? 'ROLE_ADMIN' : 'ROLE_CLIENT']);
                $user->setIsActive($request->request->get('isActive') ? true : false);

                if ($password !== '') {
                    $user->setPassword($this->hasher->hashPassword($user, $password));
                }

                $this->em->flush();

                $this->addFlash('success', 'User updated.');

                return $this->redirectToRoute('app_admin_user_index');
            }
        }

        return $this->render('admin/user/edit.html.twig', [
            'user' => $user,
            'error' => $error,
            'email' => $request->isMethod('POST') ? $request->request->get('email') : $user->getEmail(),
            'fullName' => $request->isMethod('POST') ? $request->request->get('fullName') : $user->getFullName(),
            'company' => $request->isMethod('POST') ? $request->request->get('company') : $user->getCompany(),
            'role' => $request->isMethod('POST') ? $request->request->get('role') : ($user->isAdmin() ? 'ROLE_ADMIN' : 'ROLE_CLIENT'),
            'isActive' => $request->isMethod('POST') ? $request->request->get('isActive') !== null : $user->isActive(),
        ]);
    }

    #[Route('/{id}', name: 'app_admin_user_delete', methods: ['POST'], requirements: ['id' => '\d+'])]
    public function delete(User $user, Request $request): Response
    {
        $this->denyAccessUnlessGranted('ROLE_ADMIN');

        if (!$this->isCsrfTokenValid('user_delete'.$user->getId(), $request->request->get('_token'))) {
            throw $this->createAccessDeniedException('Invalid CSRF token.');
        }

        if ($user->getId() === $this->getUser()?->getId()) {
            $this->addFlash('danger', 'You cannot delete your own account.');

            return $this->redirectToRoute('app_admin_user_index');
        }

        foreach ($user->getDomains() as $domain) {
            $domain->setOwner(null);
        }

        $this->em->remove($user);
        $this->em->flush();

        $this->addFlash('success', 'User deleted.');

        return $this->redirectToRoute('app_admin_user_index');
    }

    #[Route('/{id}/toggle', name: 'app_admin_user_toggle', methods: ['POST'], requirements: ['id' => '\d+'])]
    public function toggle(User $user, Request $request): Response
    {
        $this->denyAccessUnlessGranted('ROLE_ADMIN');

        if (!$this->isCsrfTokenValid('user_toggle'.$user->getId(), $request->request->get('_token'))) {
            throw $this->createAccessDeniedException('Invalid CSRF token.');
        }

        if ($user->getId() === $this->getUser()?->getId()) {
            $this->addFlash('danger', 'You cannot deactivate your own account.');

            return $this->redirectToRoute('app_admin_user_index');
        }

        $user->setIsActive(!$user->isActive());
        $this->em->flush();

        $this->addFlash('success', $user->isActive() ? 'User activated.' : 'User deactivated.');

        return $this->redirectToRoute('app_admin_user_index');
    }
}
