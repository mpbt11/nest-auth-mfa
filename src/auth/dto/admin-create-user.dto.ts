import { IsEmail, IsString, MinLength, IsOptional } from 'class-validator';

export class AdminCreateUserDto {
    @IsString()
    @MinLength(2)
    name: string;

    @IsEmail()
    email: string;

    @IsString()
    @IsOptional()
    group?: string;
}
