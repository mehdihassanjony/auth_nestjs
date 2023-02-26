import { BadRequestException } from '@nestjs/common';
import { Transform } from 'class-transformer';
import {
  IsEmail,
  IsNotEmpty,
  IsString,
  Matches,
  MinLength,
} from 'class-validator';
import { PHONE_VALIDATE_REGEX } from 'src/common/constants';

export class LoginDto {
  @Matches(PHONE_VALIDATE_REGEX, { message: 'Invalid phone no provided.' })
  @IsNotEmpty()
  @IsString()
  phone: string;

  @IsNotEmpty()
  @IsString()
  @MinLength(12)
  @Transform(({ value }) => {
    let nc = 0, // number count
      uc = 0, // uppercase count
      lc = 0, // lowercase count
      sc = 0; // symbol count

    value.split('').forEach((char: string) => {
      const asciiVal = char.charCodeAt(0);

      if (asciiVal >= 65 && asciiVal <= 90) {
        uc += 1;
      } else if (asciiVal >= 97 && asciiVal <= 122) {
        lc += 1;
      } else if (asciiVal >= 48 && asciiVal <= 57) {
        nc += 1;
      } else {
        sc += 1;
      }
    });

    if (uc === 0 || lc === 0 || nc === 0 || sc === 0) {
      throw new BadRequestException(
        'Password should be a combination of uppercase letters, lowercase letters, numbers, and symbols.',
      );
    }

    return value;
  })
  readonly password: string;
}
