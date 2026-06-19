import { IsString, IsEmail, IsOptional, MinLength } from 'class-validator';

export class CreateGroupDto {
    @IsString()
    @MinLength(2)
    name: string;

    @IsString()
    @IsOptional()
    description?: string;
}

export class GroupMembershipDto {
    @IsEmail()
    email: string;

    @IsString()
    @MinLength(2)
    group: string;
}
