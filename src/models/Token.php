<?php

namespace Varhall\Securino\Models;

use Varhall\Dbino\Model;
use Varhall\Dbino\Plugins\JsonPlugin;
use Varhall\Dbino\Plugins\TimestampPlugin;

class Token extends Model
{
    protected function plugins()
    {
        return [
            new TimestampPlugin(),
            new JsonPlugin([ 'data' ])
        ];
    }

    protected function softDeletes()
    {
        return FALSE;
    }

    protected function table()
    {
        return 'sessions';
    }
}