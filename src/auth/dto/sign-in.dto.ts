import { IsString, MinLength } from 'class-validator';
import { IsStrongPassword } from '../decorators/password.decorator';

export class SignInDto {
    @IsString()
    @MinLength(3)
    email: string;

    @IsString()
    @IsStrongPassword()
    password: string;
} 