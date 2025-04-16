import { ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from "generated/prisma/runtime/library";

@Injectable()
export class AuthService {
    constructor(private prismaService: PrismaService) {}

    async signup(dto: AuthDto) {
        try {
            //generate the password hash
            const hash = await argon.hash(dto.password);
    
            // save the new user in the db
            const user = await this.prismaService.user.create({
                data: {
                    email: dto.email,
                    hash
                },
                select: {  // Explicitly select fields to return (exclude hash)
                    id: true,
                    email: true,
                    // Include other user fields as needed
                },
            });

            //return the saved user
            return user;
        } catch (error) {
            if (error instanceof PrismaClientKnownRequestError) {
                if (error.code === 'P2002') {
                    throw new ForbiddenException(
                        'Credentials taken'
                    );
                }
            }
            throw error;
        }
    }

    async signin(dto: AuthDto) {
    // Find the user by email
    const user = await this.prismaService.user.findUnique({
        where: { email: dto.email }
    });

    if (!user) throw new ForbiddenException('Credentials incorrect');

    // Verify password
    const passwordMatches = await argon.verify(user.hash, dto.password);
    if (!passwordMatches) throw new ForbiddenException('Credentials incorrect');

    // Return user WITHOUT the hash property
    const { hash, ...userWithoutHash } = user;
    return userWithoutHash;
}
}