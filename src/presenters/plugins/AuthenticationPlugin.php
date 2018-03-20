<?php

namespace Varhall\Securino\Presenters\Plugins;

use Varhall\Restino\Presenters\Plugins\Plugin;


/**
 * Security plugin which checks user's authentication status
 *
 * @author Ondrej Sibrava <sibrava@varhall.cz>
 */
class AuthenticationPlugin extends Plugin
{
    protected function handle(array &$data, \Nette\Application\UI\Presenter $presenter, $method)
    {
        if (!$presenter->user->isLoggedIn())
            return $this->terminate('User is not authenticated', \Nette\Http\Response::S401_UNAUTHORIZED);
    }
}
