<?php

namespace Varhall\Securino\Storages;


class FileTokenStorage implements ITokenStorage
{
    protected $directory = '';

    protected $file = '';

    public function __construct($directory, $file)
    {
        $this->directory = $directory;
        $this->file = $file;
    }


    public function save($id, $token, $data)
    {
        $tokens = $this->readStorageFile();

        $values = [
            'id'            => $id,
            'user_id'       => $data['data']['id'],
            'token'         => $token,
            'valid_until'   => $data['exp'],
            'data'          => $data
        ];

        $tokens[$id] = $values;
        $this->writeTokenStorageFile($tokens);
    }

    public function get($id)
    {
        $tokens = $this->readStorageFile();

        return isset($tokens[$id]) ? $tokens[$id] : FALSE;
    }

    public function isActive($id)
    {
        $tokens = $this->readStorageFile();

        return isset($tokens[$id]) && $this->isActiveToken($tokens[$id]);
    }

    public function destroy($id)
    {
        $tokens = $this->readStorageFile();

        if (isset($tokens[$id])) {
            unset($tokens[$id]);

            $this->writeTokenStorageFile($tokens);
        }
    }


    /// PROTECTED METHODS

    protected function isActiveToken($token)
    {
        return empty($token['valid_until']) || intval($token['valid_until']) >= time();
    }

    /**
     * Name of file where the migrations log is stored
     *
     * @return string
     */
    protected function storageFileName()
    {
        return $this->directory . DIRECTORY_SEPARATOR . $this->file . '.json';
    }

    /**
     * Reads token storage file. If file does not exist or file is not readable, empty array is returned.
     *
     * @return array
     */
    protected function readStorageFile()
    {
        if (!file_exists($this->storageFileName()))
            return [];

        try {
            $data = file_get_contents($this->storageFileName());
            return \Nette\Utils\Json::decode($data, \Nette\Utils\Json::FORCE_ARRAY);

        } catch (\Exception $ex) {
            return [];
        }
    }

    protected function writeTokenStorageFile(array $data)
    {
        foreach ($data as $id => $token) {
            if (!$this->isActiveToken($id))
                unset($data[$id]);
        }

        if (!file_exists($this->directory))
            mkdir($this->directory, TRUE);

        file_put_contents($this->storageFileName(), \Nette\Utils\Json::encode($data));
    }
}