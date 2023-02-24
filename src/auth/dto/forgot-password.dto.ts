import { IsNotEmpty, IsString, Matches } from 'class-validator';
import { PHONE_VALIDATE_REGEX } from 'src/common/constants';

export class ForgotPasswordDto {
  @Matches(PHONE_VALIDATE_REGEX, { message: 'Invalid phone no provided.' })
  @IsNotEmpty()
  @IsString()
  phone: string;
}
