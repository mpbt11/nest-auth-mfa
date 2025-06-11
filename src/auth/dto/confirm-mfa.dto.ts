import { IsString, Length } from 'class-validator';

export class ConfirmMfaDto {
    @IsString()
    email: string;

    @IsString()
    @Length(6, 6)
    code: string;

    @IsString()
    session: string;
} 