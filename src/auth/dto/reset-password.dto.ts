import { IsString, IsEmail, MinLength } from 'class-validator';

export class ResetPasswordDto {
    @IsEmail()
    email: string;

    @IsString()
    code: string;

    @IsString()
    @MinLength(8)
    newPassword: string;
} 