<?php

namespace Varhall\Securino\Storages;

interface ITokenStorage
{
    public function save($id, $token);

    public function get($id);

    public function isActive($id);

    public function destroy($id);
}