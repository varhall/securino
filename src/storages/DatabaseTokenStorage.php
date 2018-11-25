<?php

namespace Varhall\Securino\Storages;


use Nette\Utils\DateTime;
use Varhall\Securino\Models\Token;

class DatabaseTokenStorage implements ITokenStorage
{

    public function save($id, $token, $data)
    {
        $obj = Token::find($id);

        $values = [
            'id'            => $id,
            'user_id'       => $data['data']['id'],
            'token'         => $token,
            'valid_until'   => DateTime::from($data['exp']),
            'data'          => $data
        ];

        if (!$obj)
            Token::create($values);
        else
            $obj->update($values);

        $this->clean();
    }

    public function get($id)
    {
        return Token::find($id);
    }

    public function isActive($id)
    {
        $token = $this->get($id);

        return $token && $token->valid_until >= new DateTime();
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
        Token::where('valid_until < ?', new DateTime())->delete();
    }
}