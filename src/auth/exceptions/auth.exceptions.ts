import { HttpException, HttpStatus } from '@nestjs/common';

export class InvalidCredentialsException extends HttpException {
    constructor(message: string = 'Credenciais inválidas') {
        super(message, HttpStatus.UNAUTHORIZED);
    }
}

export class UserNotFoundException extends HttpException {
    constructor(message: string = 'Usuário não encontrado') {
        super(message, HttpStatus.NOT_FOUND);
    }
}

export class UserAlreadyExistsException extends HttpException {
    constructor(message: string = 'Usuário já existe') {
        super(message, HttpStatus.CONFLICT);
    }
}

export class MissingFieldsException extends HttpException {
    constructor(fields: string[]) {
        super(
            `Campos obrigatórios ausentes: ${fields.join(', ')}`,
            HttpStatus.BAD_REQUEST
        );
    }
} 