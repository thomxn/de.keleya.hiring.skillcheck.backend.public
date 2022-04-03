import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  ParseIntPipe,
  Patch,
  Post,
  Query,
  Req,
  UseGuards,
  UnauthorizedException,
  HttpCode,
  Logger,
} from '@nestjs/common';
import { Request } from 'express';
import { AuthenticateUserDto } from './dto/authenticate-user.dto';
import { CreateUserDto } from './dto/create-user.dto';
import { DeleteUserDto } from './dto/delete-user.dto';
import { FindUserDto } from './dto/find-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { UserService } from './user.service';
import { BearerToken, LoggedInUser } from 'src/common/decorators/auth.decorator';
import { JWTPayload } from './dto/interfaces';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';

@Controller('user')
export class UserController {
  constructor(private readonly usersService: UserService) {}

  @UseGuards(JwtAuthGuard)
  @Get()
  async find(@Query() findUserDto: FindUserDto, @LoggedInUser() loggedInUser: JWTPayload, @Req() req: Request) {
    if (!loggedInUser.isAdmin) {
      return [loggedInUser];
    }
    return this.usersService.find(findUserDto);
  }

  @UseGuards(JwtAuthGuard)
  @Get(':id')
  async findUnique(@Param('id', ParseIntPipe) id, @LoggedInUser() loggedInUser: JWTPayload, @Req() req: Request) {
    if (!loggedInUser.isAdmin && loggedInUser.id != id) {
      throw new UnauthorizedException();
    }
    return await this.usersService.findUnique({ id });
  }

  @Post()
  async create(@Body() createUserDto: CreateUserDto) {
    return this.usersService.create(createUserDto);
  }

  @UseGuards(JwtAuthGuard)
  @Patch()
  async update(@Body() updateUserDto: UpdateUserDto, @LoggedInUser() loggedInUser: JWTPayload, @Req() req: Request) {
    if (!loggedInUser.isAdmin && loggedInUser.id != updateUserDto.id) {
      throw new UnauthorizedException();
    }
    return this.usersService.update(updateUserDto);
  }

  @UseGuards(JwtAuthGuard)
  @Delete()
  async delete(@Body() deleteUserDto: DeleteUserDto, @LoggedInUser() loggedInUser: JWTPayload, @Req() req: Request) {
    if (!loggedInUser.isAdmin) {
      throw new UnauthorizedException();
    }
    return this.usersService.delete(deleteUserDto);
  }

  @Post('validate')
  @HttpCode(200)
  async userValidateToken(@BearerToken() token: string, @Req() req: Request) {
    return await this.usersService.validateToken(token);
  }

  @Post('authenticate')
  @HttpCode(200)
  async userAuthenticate(@Body() authenticateUserDto: AuthenticateUserDto) {
    return await this.usersService.authenticate(authenticateUserDto);
  }

  @Post('token')
  @HttpCode(200)
  async userGetToken(@Body() authenticateUserDto: AuthenticateUserDto) {
    return await this.usersService.authenticateAndGetJwtToken(authenticateUserDto);
  }
}
