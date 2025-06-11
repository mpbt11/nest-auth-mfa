import { IsString, IsEmail, MinLength, IsEnum, Matches, IsISO8601 } from 'class-validator';

export enum Gender {
    MALE = 'male',
    FEMALE = 'female',
    OTHER = 'other'
}

export class RegisterDto {
    @IsEmail()
    email: string;

    @IsString()
    @MinLength(8)
    password: string;

    @IsString()
    @MinLength(3)
    nickname: string;

    @IsString()
    @MinLength(3)
    name: string;

    @IsString()
    @MinLength(3)
    address: string;

    @IsISO8601()
    birthdate: string;

    @IsEnum(Gender)
    gender: Gender;

    @Matches(/^\+55[1-9]{2}[0-9]{8,9}$/, {
        message: 'Phone number must be in format +55DDXXXXXXXXX (Example: +5514998018683)'
    })
    phone_number: string;
} 