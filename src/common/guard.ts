import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtStrategy } from 'src/auth/jwt.strategy';
import { UserTokenPayloadDto } from './common-dto';

@Injectable()
export class AuthorizeGuard implements CanActivate {
  constructor(private readonly jwtStragey: JwtStrategy) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<any>();

    const user: UserTokenPayloadDto = await this.jwtStragey.validateToken(req);

    req.user = user;

    return true;
  }
}
