import { IsString, IsEmail } from 'class-validator';

export class ChallengeResponseDto {
    @IsEmail()
    email: string;

    @IsString()
    session: string;

    @IsString()
    code: string;
} 