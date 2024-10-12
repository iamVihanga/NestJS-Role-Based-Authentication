import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class UserService {
  constructor(private prisma: PrismaService) {}

  // Find a User by email
  async findByEmail(email: string) {
    return await this.prisma.user.findFirst({
      where: { email },
      include: { account: true },
    });
  }

  // Find a User by id
  async findById(id: string, authUser: any) {
    console.log(authUser);

    return await this.prisma.user.findUnique({
      where: { id },
      include: { account: true },
    });
  }
}
