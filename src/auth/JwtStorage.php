<?php

namespace Varhall\Securino\Auth;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Nette\Http\Request;
use Nette\Http\Response;
use Nette\InvalidStateException;
use Nette\Security\IIdentity;
use Nette\Security\SimpleIdentity;
use Nette\Utils\DateTime;
use Varhall\Securino\Storages\ITokenStorage;

class JwtStorage implements \Nette\Security\IUserStorage
{
    const AUTH_HEADER = 'Authorization';

    protected $key = '';

    protected $algorithm = '';

    /**
     * @var ITokenStorage
     */
    protected $tokenStorage = NULL;

    /**
     * @var null|Request
     */
    protected $request = NULL;

    /**
     * @var null|Response
     */
    protected $response = NULL;


    // IUserStorage properties

    /**
     * @var IIdentity
     */
    protected $identity = NULL;

    protected $token = NULL;

    protected $expiration = NULL;


    public function __construct($key, $algorithm, ITokenStorage $tokenStorage, Request $request, Response $response)
    {
        $this->key = $key;
        $this->algorithm = $algorithm;
        $this->tokenStorage = $tokenStorage;
        $this->request = $request;
        $this->response = $response;
    }


    /// IUserStorage interface implementation

    /**
     * Sets the authenticated status of this user.
     * @param  bool
     * @return static
     */
    function setAuthenticated(bool $state)
    {
        if (!$state && $this->isAuthenticated()) {
            $this->tokenStorage->destroy($this->deserializeToken()->jti);
            $this->setIdentity(NULL);       // TODO: zvazit zda vzdy mazat identitu - request se bude tvarit jako prihlaseny do jeho skonceni
        }
    }

    /**
     * Is this user authenticated?
     * @return bool
     */
    function isAuthenticated(): bool
    {
        return !!$this->getIdentity();
    }

    /**
     * Sets the user identity.
     * @return static
     */
    function setIdentity(\Nette\Security\IIdentity $identity = null)
    {
        $this->identity = $identity;
    }

    /**
     * Returns current user identity, if any.
     * @return \Nette\Security\IIdentity|null
     */
    function getIdentity(): ?IIdentity
    {
        if (!$this->identity) {
            try {
                $this->identity = $this->deserializeToken();

            } catch (\Exception $ex) {
                return NULL;
            }
        }

        return $this->identity;
    }

    /**
     * Enables log out from the persistent storage after inactivity.
     * @param  string|int|\DateTimeInterface number of seconds or timestamp
     * @param  int  flag IUserStorage::CLEAR_IDENTITY
     * @return static
     */
    function setExpiration(?string $time, int $flags = 0)
    {
        // TODO: flags

        $this->expiration = $time;
    }

    /**
     * Why was user logged out?
     * @return int|null
     */
    function getLogoutReason(): ?int
    {
        // TODO: Implement getLogoutReason() method.
        return null;
    }




    /// Storage methods

    public function generateToken()
    {
        if (!$this->isAuthenticated())
            throw new InvalidStateException('User is not authenticated');

        $now = new DateTime();

        $data = [
            'iat'   => $now->getTimestamp(),                                                     // Issued at: time when the token was generated
            'jti'   => md5($this->identity->getId() . $now->getTimestamp()),              // Json Token Id: an unique identifier for the token
            'iss'   => $_SERVER['SERVER_NAME'],                                                  // Issuer
            'nbf'   => $now->getTimestamp(),                                                     // Not before
            'exp'   => !empty($this->expiration)                                                 // Expire
                ? $now->modifyClone("+{$this->expiration}")->getTimestamp()
                : NULL,
            'sub'   => $this->identity->getId(),
            'roles' => $this->identity->getRoles(),
            'data'  => $this->identity->getData(),
        ];

        $token = JWT::encode($data, $this->key, $this->algorithm);
        $this->tokenStorage->save($data['jti'], $token, $data);

        return $token;
    }

    protected function deserializeToken()
    {
        $token = $this->request->getHeader(self::AUTH_HEADER);

        $matches = [];
        if (empty($token) || !preg_match('/^Bearer (.+)$/i', $token, $matches))
            throw new InvalidTokenException([], 'Missing or invalid \'Authorization\' HTTP header');

        $data = JWT::decode($matches[1], new Key($this->key, $this->algorithm));

        return new SimpleIdentity($data->sub, $data->roles ?? [], (array) ($data->data ?? []));
    }
}
