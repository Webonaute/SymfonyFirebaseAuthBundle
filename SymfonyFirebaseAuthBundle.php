<?php

namespace Webonaute\SymfonyFirebaseAuthBundle;

use Symfony\Bundle\SecurityBundle\DependencyInjection\SecurityExtension;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;
use Webonaute\SymfonyFirebaseAuthBundle\DependencyInjection\Security\Factory\GetJWTFactory;

class SymfonyFirebaseAuthBundle extends Bundle
{
    /**
     * @param ContainerBuilder $container
     */
    public function build(ContainerBuilder $container)
    {
        /** @var SecurityExtension $extension */
        $extension = $container->getExtension('security');
        $extension->addSecurityListenerFactory(new GetJWTFactory());
    }
}
