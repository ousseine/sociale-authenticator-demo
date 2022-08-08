<?php

namespace App\Exceptions;

use Symfony\Component\Security\Core\Exception\CustomUserMessageAccountStatusException;

class NotVerifyException extends CustomUserMessageAccountStatusException
{
    public function __construct(
        string $message = "Ce compte ne semble pas posséder d'email vérifié",
        array $messageData = [],
        int $code = 0,
        \Throwable $previous = null
    )
    {
        parent::__construct($message, $messageData, $code, $previous);
    }
}