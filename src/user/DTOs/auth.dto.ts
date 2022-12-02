import { IsString, IsNotEmpty, IsEmail, MinLength, IsBoolean } from "class-validator"

export class SignupDto {

    @IsString()
    @IsNotEmpty()
    username: string;

    @IsEmail()
    email: string;

    @IsString()
    @MinLength(5)
    password: string;

    @IsBoolean()
    status: boolean
}