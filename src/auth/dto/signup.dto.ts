import { IsEmail, IsNotEmpty, IsString, Matches, MinLength } from 'class-validator';
import { AbstractEntity } from 'src/common/abstract-entity';
import { PHONE_VALIDATE_REGEX } from 'src/common/constants';

export class SignUpDto {
  @IsNotEmpty()
  @IsString()
  readonly name: string;

  @IsNotEmpty()
  @IsEmail({}, { message: 'Please enter correct email' })
  readonly email: string;

  @Matches(PHONE_VALIDATE_REGEX, { message: 'Invalid phone no provided.' })
  @IsNotEmpty()
  @IsString()
  phone: string;

  @IsNotEmpty()
  @IsString()
  @MinLength(6)
  readonly password: string;
}
