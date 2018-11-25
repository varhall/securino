<?php

namespace Varhall\Securino\Authorization;


trait Authorize
{
    protected $defaultPolicyResult = FALSE;

    public function can($action, $object)
    {
        $class = is_object($object) ? get_class($object) : $object;
        $object = is_object($object) ? $object : NULL;

        if (!is_string($class))
            throw new \InvalidArgumentException('$object argument is not a class or object');

        $policy = Guard::policy($class);

        if (!$policy)
            return $this->defaultPolicyResult;

        if (method_exists($policy, 'before') && ($result = call_user_func([ $policy, 'before' ], $this, $object)) !== NULL)
            return !!$result;

        return call_user_func([ $policy, $action ], $this, $object);
    }

    public function cant($action, $object)
    {
        return !$this->can($action, $object);
    }
}