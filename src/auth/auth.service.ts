import {
  BadRequestException,
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { Role } from '@prisma/client';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  async validateUser(dto: LoginDto): Promise<any> {
    const { email, password } = dto;

    const user = await this.prisma.user.findUnique({ where: { email } });

    if (user && (await bcrypt.compare(password, user.hashedPassword))) {
      const { hashedPassword, ...result } = user;
      return result;
    }

    return null;
  }

  async login(user: any) {
    const existingUser = await this.prisma.user.findUnique({
      where: { email: user.email },
    });

    const payload = {
      id: existingUser.id,
      email: existingUser.email,
      role: existingUser.role,
    };

    return {
      user: payload,
      accessToken: this.jwtService.sign(payload),
      refreshToken: await this.generateRefreshToken(existingUser.id),
    };
  }

  async generateRefreshToken(userId: string): Promise<string> {
    const refreshToken = this.jwtService.sign({ userId }, { expiresIn: '7d' });

    await this.prisma.refreshToken.create({
      data: {
        token: refreshToken,
        userId,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      },
    });

    return refreshToken;
  }

  async refreshAccessToken(refreshToken: string) {
    try {
      const payload = this.jwtService.verify(refreshToken);

      const storedToken = await this.prisma.refreshToken.findUnique({
        where: { token: refreshToken },
        include: { user: true },
      });

      if (!storedToken || storedToken.userId !== payload.userId) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      const newAccessToken = this.jwtService.sign({
        id: storedToken.userId,
        email: storedToken.user.email,
        role: storedToken.user.role,
      });

      const newRefreshToken = await this.generateRefreshToken(
        storedToken.userId,
      );

      return { accessToken: newAccessToken, refreshToken: newRefreshToken };
    } catch (error) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  async register(dto: RegisterDto) {
    const { email, password, role } = dto;

    const existingUser = await this.prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      throw new ConflictException('Email already exists');
    }

    if (password.length < 8) {
      throw new BadRequestException(
        'Password must be at least 8 characters long',
      );
    }

    // Check role is valid by checking if it exists in the enum
    if (!Object.values(Role).includes(role)) {
      throw new BadRequestException('Invalid role');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await this.prisma.user.create({
      data: {
        email,
        hashedPassword,
        role,
      },
    });

    const { hashedPassword: _, ...result } = newUser;

    return result;
  }
}
