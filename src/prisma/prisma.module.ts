import { Module } from '@nestjs/common';
import { PrismaService } from './prisma.service';
import { AuthService } from 'src/auth/auth.service';
import { JwtService } from '@nestjs/jwt';

@Module({
  providers: [PrismaService, AuthService, JwtService],
})
export class PrismaModule {}
