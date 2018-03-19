<?php

namespace Varhall\Securino\Storages;


use Varhall\Securino\Models\Token;

class DatabaseTokenStorage implements ITokenStorage
{

    public function save($id, $token)
    {
        $obj = Token::find($id);

        if (!$obj)
            Token::create($token);
        else
            $obj->update($token);

        $this->clean();
    }

    public function get($id)
    {
        return Token::find($id);
    }

    public function isActive($id)
    {
        $token = $this->get($id);

        return $token && $token->exp >= time();
    }

    public function destroy($id)
    {
        $token = Token::find($id);

        if ($token)
            $token->delete();

        $this->clean();
    }

    protected function clean()
    {
        Token::where('exp < ?', time())->delete();
    }
}