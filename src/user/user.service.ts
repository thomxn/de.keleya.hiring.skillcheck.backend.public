import {
  Body,
  Injectable,
  ConflictException,
  Post,
  UnauthorizedException,
  ConsoleLogger,
  Logger,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Prisma, User } from '@prisma/client';
import { PrismaService } from '../prisma.services';
import { AuthenticateUserDto } from './dto/authenticate-user.dto';
import { CreateUserDto } from './dto/create-user.dto';
import { DeleteUserDto } from './dto/delete-user.dto';
import { FindUserDto } from './dto/find-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { UserSearchClause, UserUpdatePayload, JWTPayload } from './dto/interfaces';
import { hashPassword, matchHashedPassword } from '../common/utils/password';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class UserService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly appConfig: ConfigService,
  ) {}

  /**
   * Finds users with matching fields
   *
   * @param findUserDto
   * @returns User[]
   */
  async find(findUserDto: FindUserDto): Promise<User[]> {
    const { id, name, email, updatedSince, limit, offset, credentials } = findUserDto;
    const searchClause: UserSearchClause = {};
    if (email) searchClause.email = { contains: email };
    if (name) searchClause.name = { contains: name };
    if (updatedSince) searchClause.updated_at = { gte: new Date(findUserDto.updatedSince) };
    if (id) searchClause.id = { in: id.map((_id) => Number(_id)) };
    const users = await this.prisma.user.findMany({
      skip: offset ? Number(offset) : undefined,
      take: limit ? Number(limit) : undefined,
      where: searchClause,
      include: { credentials: credentials },
    });

    return users;
  }

  async findUnique(whereUnique: Prisma.UserWhereUniqueInput) {
    const user = await this.prisma.user.findUnique({
      where: whereUnique,
    });
    return user;
  }

  @Post('user')
  async create(@Body() createUserDto: CreateUserDto) {
    const { email, name, isAdmin } = createUserDto;
    if (await this.emailExists(email)) throw new ConflictException('Email is taken');
    const hashedPassword = await hashPassword(createUserDto.password);
    return await this.prisma.user.create({
      data: {
        name,
        email,
        emailConfirmed: false,
        isAdmin: isAdmin,
        credentials: {
          create: {
            hash: hashedPassword,
          },
        },
      },
    });
  }

  async update(updateUserDto: UpdateUserDto) {
    const { id, name, email, password } = updateUserDto;
    const user = await this.findUnique({ id });
    if (!user) return null;
    if (user.isDeleted) return null;
    const payload: UserUpdatePayload = {};
    if (name) payload.name = name;
    if (email) {
      if (await this.emailExists(email)) throw new ConflictException('Email is taken');
      payload.email = email;
    }
    if (password) {
      const hash = hashPassword(password);
      payload.credentials = { credentials: { update: { where: { id: user.credentialsId }, data: { hash } } } };
    }
    const response = await this.prisma.user.update({ where: { id }, data: payload });
    const res = { ...response, createdAt: response.createdAt, updatedAt: response.updatedAt };
    return res;
  }

  async delete(deleteUserDto: DeleteUserDto) {
    console.log('hitttt');
    const { id } = deleteUserDto;
    console.log(id);
    const user = await this.findUnique({ id });
    if (user.isDeleted) return null;
    await this.prisma.user.update({
      where: { id: deleteUserDto.id },
      data: {
        isDeleted: true,
        // credentialsId: null,
        credentials: {
          delete: true
        },
      },
    });

    return { msg: 'user deleted' };
  }

  async authenticateAndGetJwtToken(authenticateUserDto: AuthenticateUserDto) {
    const authenticatedUser = await this.authCheck(authenticateUserDto);
    if (!authenticatedUser) throw new UnauthorizedException();
    const { id, email, isAdmin } = authenticatedUser;
    const payload: JWTPayload = { id, email, isAdmin };
    const token = await this.jwtService.signAsync(payload);
    return { token };
  }


  async authenticate(authenticateUserDto: AuthenticateUserDto) {
    const authenticatedUser = await this.authCheck(authenticateUserDto);
    if (!authenticatedUser) return { credentials: false };
    return { credentials: true };
  }


  async validateToken(token: string) {
    const secret = this.appConfig.get<string>('JWT_SECRET');
    const decoded = await this.jwtService.verifyAsync(token, { secret });
    if (decoded) return decoded;
  }


  async emailExists(email: string) {
    return await this.prisma.user.findUnique({ where: { email } });
  }

  async authCheck(authenticateUserDto: AuthenticateUserDto): Promise<User> {
    const { email, password } = authenticateUserDto;
    const user = await this.prisma.user.findUnique({
      where: { email },
      include: { credentials: true },
    });
    if (!user) return null;
    const isValidPassword = await matchHashedPassword(password, user.credentials.hash);
    if (!isValidPassword) return null;
    return user;
  }
}
