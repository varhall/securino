<?php

namespace Varhall\Securino\Authorization;


class Role
{
    private static $roles = [];

    private $name = '';

    public static function add($roles)
    {
        self::$roles = array_merge(self::$roles, $roles);
    }

    public static function get($name)
    {
        if (!isset(self::$roles[$name]))
            throw new \InvalidArgumentException("Undefined role $name");

        return new Role($name);
    }

    public function __construct($name)
    {
        $this->name = $name;
    }

    public function __get($name)
    {
        if (method_exists($this, $name))
            return call_user_func([ $this, $name ]);

        throw new \BadMethodCallException("Undefined method $name");
    }

    public function parents()
    {
        return array_map(function($parent) {
            return new Role($parent);
        }, self::$roles[$this->name]);
    }

    public function is($role)
    {
        if ($role === $this->name)
            return TRUE;

        foreach ($this->parents as $p) {
            if ($p->is($role))
                return TRUE;
        }

        return FALSE;
    }
}