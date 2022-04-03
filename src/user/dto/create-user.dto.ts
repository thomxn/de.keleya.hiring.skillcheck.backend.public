import { IsNotEmpty, IsEmail, IsBoolean, isBoolean } from 'class-validator'

export class CreateUserDto {
  @IsNotEmpty()
  readonly name: string

  @IsNotEmpty()
  @IsEmail()
  readonly email: string

  @IsNotEmpty()
  readonly password: string

  @IsBoolean()
  readonly isAdmin?: boolean
}
