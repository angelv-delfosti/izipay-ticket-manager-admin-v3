import { IsString, IsNotEmpty, IsEmail, MinLength, IsBoolean, IsEnum, IsOptional } from "class-validator"
import { Role } from '@prisma/client';

export class SignupDto {

    @IsString()
    @IsNotEmpty()
    username: string;

    @IsEmail()
    email: string;

    @IsString()
    @MinLength(8)
    password: string;

    @IsBoolean()
    status: boolean;

    @IsOptional()
    @IsString()
    @IsNotEmpty()
    key?: string;
}

export class SigninDto {
    @IsEmail()
    email: string;

    @IsString()
    password: string;
}


export class GenerateRoleKeyDto {
    @IsEmail()
    email: string;

    @IsEnum(Role)
    role: Role;
}