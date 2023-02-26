import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './schemas/user.schema';
import * as jwt from 'jsonwebtoken';
import { UserTokenPayloadDto } from 'src/common/common-dto';

@Injectable()
export class JwtStrategy {
  constructor(
    @InjectModel(User.name)
    private userModel: Model<User>,
  ) {}

  async validateToken(req): Promise<UserTokenPayloadDto> {
    if (!req.headers.authorization) {
      throw new UnauthorizedException('Token not found in header');
    }

    const token = req.headers.authorization.replace('Bearer ', '');

    try {
      const tokenPayload: UserTokenPayloadDto = (await jwt.verify(
        token,
        process.env.JWT_SECRET,
      )) as UserTokenPayloadDto;

      return tokenPayload;
    } catch (error) {
      throw new UnauthorizedException(error);
    }
  }

  async sign(query) {
    const user = await this.userModel.findOne(query);

    const token = await jwt.sign(
      {
        _id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        emailVerified: user.emailVerified,
        phoneVerified: user.phoneVerified,
      },
      process.env.JWT_SECRET,
      { expiresIn: '10d' },
    );

    return token;
  }
}
