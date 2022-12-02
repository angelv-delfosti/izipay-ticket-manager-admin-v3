import { ConflictException, Injectable } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import * as bcrypt from 'bcryptjs';
import { Role } from '@prisma/client'

interface SignupParams {
    email: string;
    password: string;
    username: string;
    status: boolean;
}

@Injectable()
export class AuthService {
    constructor(private readonly prismaService: PrismaService) { }
    async signup({ email, password, username, status }: SignupParams) {
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
                role: Role.admin
            }
        });
        return user
    }
}       
