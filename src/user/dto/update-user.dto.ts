import { IsNotEmpty, IsString, isEmail, IsEmail } from 'class-validator';

export class UpdateUserDto {

  @IsString()
  readonly password?: string;
  
  @IsString()
  readonly name?: string;

  @IsString()
  @IsEmail()
  readonly email?: string;

  @IsNotEmpty()
  readonly id: number;
}