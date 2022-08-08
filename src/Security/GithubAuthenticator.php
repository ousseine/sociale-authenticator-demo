<?php

namespace App\Security;

use App\Entity\User;
use App\Exceptions\NotVerifyException;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Client\OAuth2ClientInterface;
use KnpU\OAuth2ClientBundle\Security\Authenticator\OAuth2Authenticator;
use League\OAuth2\Client\Provider\GithubResourceOwner;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\Security\Http\Util\TargetPathTrait;
use Symfony\Contracts\HttpClient\Exception\ClientExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\RedirectionExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\ServerExceptionInterface;

class GithubAuthenticator extends OAuth2Authenticator implements AuthenticationEntryPointInterface
{
    use TargetPathTrait;

    private RouterInterface $router;
    private ClientRegistry $clientRegistry;
    private EntityManagerInterface $manager;
    private UserRepository $userRepository;

    public function __construct(
        RouterInterface $router,
        ClientRegistry $clientRegistry,
        EntityManagerInterface $manager,
        UserRepository $userRepository,
    )
    {
        $this->router = $router;
        $this->clientRegistry = $clientRegistry;
        $this->manager = $manager;
        $this->userRepository = $userRepository;
    }

    public function start(Request $request, AuthenticationException $authException = null): RedirectResponse
    {
        return new RedirectResponse($this->router->generate('app_login'));
    }

    public function supports(Request $request): ?bool
    {
        return 'oaut2_github_check' === $request->attributes->get('_route') && $request->get('service') === 'github';
    }

    /**
     * @throws ServerExceptionInterface
     * @throws RedirectionExceptionInterface
     * @throws ClientExceptionInterface
     */
    public function authenticate(Request $request): Passport
    {
        $client = $this->getClient();
        $accessToken = $this->fetchAccessToken($client);

        return new SelfValidatingPassport(
            new UserBadge($accessToken->getToken(), function () use ($accessToken, $client) {
                /** @var GithubResourceOwner $githubUser */
                $githubUser = $client->fetchUserFromToken($accessToken);

                // On récupère l'email de github
                $response = HttpClient::create()->request(
                    'GET',
                    'https://api.github.com/user/emails',
                    [
                        'headers' => ['authorization' => "token {$accessToken->getToken()}"]
                    ]
                );

                $emails = json_decode($response->getContent(), true);

                foreach ($emails as $email) {
                    if ($email['primary'] === true && $email['verified'] === true) {
                        $data = $githubUser->toArray();
                        $data['email'] = $email['email'];
                        $githubUser = new GithubResourceOwner($data);
                    }
                }

                if ($githubUser->getEmail() === null) throw new NotVerifyException();

                $user = $this->userRepository->findOneBy(['githubId' => $githubUser->getId()]);

                if ($user) return $user;

                $user = (new User())
                    ->setRoles(["ROLE_USER"])
                    ->setEmail($githubUser->getEmail())
                    ->setGithubId($githubUser->getId())
                ;
                $this->manager->persist($user);
                $this->manager->flush();

                return $user;
            })
        );
    }

    private function getClient(): OAuth2ClientInterface
    {
        return $this->clientRegistry->getClient('github');
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        $targetPath = $this->getTargetPath($request->getSession(), $firewallName);
        $targetUrl = $this->router->generate('app_home');

        return new  RedirectResponse($targetPath ? : $targetUrl);
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        if ($request->hasSession())
            $request->getSession()->set(Security::AUTHENTICATION_ERROR, $exception);

        return new RedirectResponse($this->router->generate('app_login'));
    }
}