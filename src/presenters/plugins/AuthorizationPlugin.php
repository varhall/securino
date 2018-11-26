<?php

namespace Varhall\Securino\Presenters\Plugins;

use Nette\Http\Response;
use Varhall\Restino\Presenters\Plugins\Plugin;
use Varhall\Restino\Presenters\RestRequest;


/**
 * Security plugin which checks user role
 *
 * @author Ondrej Sibrava <sibrava@varhall.cz>
 */
class AuthorizationPlugin extends Plugin
{
    protected function handle(RestRequest $request, $user)
    {
        $class = $this->presenterCall($request->getPresenter(), 'modelClass');

        if ($user->cant($request->method, !!$request->id ? $class::find($request->id) : $class))
            return $this->terminate('Operation is not allowed', Response::S403_FORBIDDEN);

        return $request->next();
    }
}
