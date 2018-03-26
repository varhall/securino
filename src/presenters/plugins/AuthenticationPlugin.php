<?php

namespace Varhall\Securino\Presenters\Plugins;

use Varhall\Restino\Presenters\Plugins\Plugin;
use Varhall\Restino\Presenters\RestRequest;


/**
 * Security plugin which checks user's authentication status
 *
 * @author Ondrej Sibrava <sibrava@varhall.cz>
 */
class AuthenticationPlugin extends Plugin
{
    protected  function handle(RestRequest $request, ...$args)
    {
        if (!$request->getPresenter()->user->isLoggedIn())
            return $this->terminate('User is not authenticated', \Nette\Http\Response::S401_UNAUTHORIZED);

        return $request->next();
    }
}
