import { ConflictException, Injectable, HttpException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import * as bcrypt from 'bcryptjs';
import * as jwt from 'jsonwebtoken'
import { Role } from '@prisma/client'

interface SignupParams {
    email: string;
    password: string;
    username: string;
    status: boolean;
}

interface SigninParams {
    email: string;
    password: string;
}

@Injectable()
export class AuthService {
    constructor(private readonly prismaService: PrismaService) { }
    async signup({ email, password, username, status }: SignupParams, role: Role) {
        const userExists = await this.prismaService.user.findUnique({
            where: {
                email,
            }
        })
        if (userExists) {
            throw new ConflictException();
        }
        const hashedPassword = await bcrypt.hash(password, 10)

        const user = await this.prismaService.user.create({
            data: {
                email,
                username,
                password: hashedPassword,
                status,
                role: role
            }
        });
        return this.generateJWT(user.username, user.id)
    }

    async signin({ email, password }: SigninParams) {
        const user = await this.prismaService.user.findUnique({
            where: {
                email,
            }
        })
        if (!user) {
            throw new HttpException('Invalid credencials', 400)
        }
        const hashedPassword = user.password;
        const isValidPassword = await bcrypt.compare(password, hashedPassword)

        if (!isValidPassword) {
            throw new HttpException('Invalid credencials', 400)
        }

        return this.generateJWT(user.username, user.id)
    }

    private generateJWT(username: string, id: number) {
        return jwt.sign({
            username,
            id
        }, process.env.JSON_TOKEN_KEY, {
            expiresIn: '180d'
        })
    }

    generateRoleKey(email: string, role: Role) {
        const string = `${email}-${role}-${process.env.ROLE_KEY_SECRET}`

        return bcrypt.hash(string, 10)
    }

}       
