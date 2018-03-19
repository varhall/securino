<?php

namespace Varhall\Securino\Storages;


class BlackholeTokenStorage implements ITokenStorage
{

    public function save($id, $token)
    {

    }

    public function get($id)
    {
        return FALSE;
    }

    public function isActive($id)
    {
        return TRUE;
    }

    public function destroy($id)
    {

    }
}