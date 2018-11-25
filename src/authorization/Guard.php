<?php

namespace Varhall\Securino\Authorization;


class Guard
{
    private static $instance = NULL;

    private $policies = [];

    public static function __callStatic($name, $arguments)
    {
        return call_user_func_array([ self::instance(), $name ], $arguments);
    }

    public function __call($name, $arguments)
    {
        return call_user_func_array([ $this, $name ], $arguments);
    }

    public static function instance()
    {
        if (self::$instance === NULL)
            self::$instance = new Guard();

        return self::$instance;
    }

    private function register($policies)
    {
        $this->policies = array_merge($this->policies, $policies);

        return $this;
    }

    private function unregister($class)
    {
        if (isset($this->policies[$class]))
            unset($this->policies[$class]);

        return $this;
    }

    private function policy($class)
    {
        return isset($this->policies[$class]) ? new $this->policies[$class] : NULL;
    }
}