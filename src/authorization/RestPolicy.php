<?php

namespace Varhall\Securino\Authorization;


abstract class RestPolicy
{
    public function __call($name, $arguments)
    {
        $name = 'can' . ucfirst(strtolower($name));

        if (method_exists($this, $name))
            return call_user_func_array([ $this, $name ], $arguments);

        throw new \BadMethodCallException("Call to undefined method $name");
    }

    public function canAll($user, $object = NULL)
    {
        return FALSE;
    }

    public function canRead($user, $object = NULL)
    {
        return $this->canAll($user, $object);
    }

    public function canWrite($user, $object = NULL)
    {
        return $this->canAll($user, $object);
    }

    public function canList($user)
    {
        return $this->canRead($user);
    }

    public function canGet($user, $object)
    {
        return $this->canRead($user, $object);
    }

    public function canCreate($user)
    {
        return $this->canWrite($user);
    }

    public function canUpdate($user, $object)
    {
        return $this->canWrite($user, $object);
    }

    public function canDelete($user, $object)
    {
        return $this->canWrite($user, $object);
    }

    public function canClone($user, $object)
    {
        return $this->canWrite($user, $object);
    }
}