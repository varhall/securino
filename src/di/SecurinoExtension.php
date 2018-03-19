<?php

namespace Varhall\Securino\DI;

/**
 * Description of SecurinoExtension
 *
 * @author Ondrej Sibrava <sibrava@varhall.cz>
 */
class SecurinoExtension extends \Nette\DI\CompilerExtension
{
    protected function configuration()
    {
        $builder = $this->getContainerBuilder();
        return $this->getConfig([
            'storage'           => '\Varhall\Securino\Storages\BlackholeTokenStorage',
            'expiration'        => '7 days',
            'algorithm'         => 'HS256'
        ]);
    }

    /**
     * Processes configuration data
     *
     * @return void
     */
    public function loadConfiguration()
    {
        $builder = $this->getContainerBuilder();

        $config = $this->configuration();

        if (!array_key_exists('key', $config) || !array_key_exists('algorithm', $config)) {
            throw new \UnexpectedValueException("Please configure the Securino extensions using the section '{$this->name}:' in your config file.");
        }

        $storage = $builder->addDefinition($this->prefix('userStorage'))
                        ->setFactory('Varhall\Securino\Auth\JwtStorage', [
                            $config['key'], $config['algorithm']
                        ]);

        if ($config['expiration']) {
            $storage->addSetup('setExpiration', [ $config['expiration'] ]);
        }

        $builder->addDefinition($this->prefix('tokenStorage'))->setFactory($config['storage']);

        // Disable default user storage
        $builder->getDefinition('security.userStorage')->setAutowired(false);
    }
}
