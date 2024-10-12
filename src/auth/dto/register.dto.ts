import { IsEmail, IsString } from 'class-validator';
import { Role } from '@prisma/client';

export class RegisterDto {
  @IsEmail()
  email: string;

  @IsString()
  password: string;

  role: Role = Role.USER;
}
