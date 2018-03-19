<?php

namespace Varhall\Securino\Auth;

use Nette\InvalidArgumentException;
use Throwable;

class InvalidTokenException extends InvalidArgumentException
{
    protected $token = [];

    public function __construct($token, $message = "", $code = 0, Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);

        $this->token = $token;
    }

    public function getToken()
    {
        return $this->token;
    }
}