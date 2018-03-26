<?php

namespace Varhall\Securino\Presenters\Plugins;

use Varhall\Restino\Presenters\Plugins\Plugin;
use Varhall\Restino\Presenters\RestRequest;


/**
 * Security plugin which checks user role
 *
 * @author Ondrej Sibrava <sibrava@varhall.cz>
 */
class AuthorizationPlugin extends Plugin
{
    protected  function handle(RestRequest $request, ...$args)
    {
        if (!$request->getPresenter()->user->isLoggedIn())
            $this->terminate('User is not authenticated', \Nette\Http\Response::S401_UNAUTHORIZED);

        $this->checkPermission($request->getPresenter(), $request->method);

        return $request->next();
    }

    protected function checkPermission(\Nette\Application\UI\Presenter $presenter, $method)
    {
        if (!$presenter->user->isAllowed($presenter->getRequest()->getPresenterName(), $method))
            return $this->terminate('Method is not allowed', \Nette\Http\Response::S403_FORBIDDEN);
    }
}
