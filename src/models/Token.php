<?php

namespace Varhall\Securino\Models;

use Varhall\Dbino\Model;
use Varhall\Dbino\Traits\Timestamps;

class Token extends Model
{
    use Timestamps;

    protected function table()
    {
        return 'sessions';
    }
}