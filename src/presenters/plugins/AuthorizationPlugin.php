<?php

namespace Varhall\Securino\Presenters\Plugins;

use Varhall\Restino\Presenters\Plugins\Plugin;


/**
 * Security plugin which checks user role
 *
 * @author Ondrej Sibrava <sibrava@varhall.cz>
 */
class AuthorizationPlugin extends Plugin
{
    protected function handle(array &$data, \Nette\Application\UI\Presenter $presenter, $method)
    {
        if (!$presenter->user->isLoggedIn())
            $this->terminate('User is not authenticated', \Nette\Http\Response::S401_UNAUTHORIZED);

        $this->checkPermission($presenter, $method);
    }

    protected function checkPermission(\Nette\Application\UI\Presenter $presenter, $method)
    {
        if (!$presenter->user->isAllowed($presenter->getRequest()->getPresenterName(), $method))
            return $this->terminate('Method is not allowed', \Nette\Http\Response::S403_FORBIDDEN);
    }
}
