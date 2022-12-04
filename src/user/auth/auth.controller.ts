import { Controller, Post, Body, Param, ParseEnumPipe, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto, SigninDto, GenerateRoleKeyDto } from '../DTOs/auth.dto';
import { Role } from '@prisma/client';
import * as bcrypt from 'bcryptjs';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) { }
    @Post('/signup/:role')
    async signup(@Body() body: SignupDto, @Param('role', new ParseEnumPipe(Role)) role: Role) {

        if (role !== Role.visitor) {
            if (!body.key) {
                throw new UnauthorizedException()
            }
            const validKey = `${body.email}-${role}-${process.env.ROLE_KEY_SECRET}`

            const isValidKey = await bcrypt.compare(validKey, body.key)

            if (!isValidKey) {
                throw new UnauthorizedException()
            }
        }
        return this.authService.signup(body, role)
    }

    @Post('/signin')
    signin(@Body() body: SigninDto) {
        return this.authService.signin(body)
    }

    @Post('/key')
    generateRoleKey(@Body() { role, email }: GenerateRoleKeyDto) {
        return this.authService.generateRoleKey(email, role)
    }
}

