import {
  Injectable,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './schemas/user.schema';

import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { SignUpDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  constructor(
    @InjectModel(User.name)
    private userModel: Model<User>,
    private jwtService: JwtService,
  ) {}

  async signUp(signUpDto: SignUpDto): Promise<{ token: string }> {
    const { name, email, phone, password } = signUpDto;

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await this.userModel.create({
      name,
      email,
      phone,
      password: hashedPassword,
    });

    const token = this.jwtService.sign({ id: user._id });
    await this.sendSms(phone, name);
    await this.sendMail(email, name);
    return { token };
  }

  async sendSms(phone: string, message: string) {
    this.logger.log(`Successfully sent SMS to: ${phone}`);
  }

  async sendMail(email: string, message: string) {
    this.logger.log(`Successfully sent mail to: ${email}`);
  }

  async login(loginDto: LoginDto): Promise<{ token: string }> {
    const { email, password } = loginDto;

    const user = await this.userModel.findOne({ email });

    if (!user) {
      throw new UnauthorizedException('Invalid email or password');
    }

    const isPasswordMatched = await bcrypt.compare(password, user.password);

    if (!isPasswordMatched) {
      throw new UnauthorizedException('Invalid email or password');
    }

    const token = this.jwtService.sign({ id: user._id });

    return { token };
  }

  async getUserDetail(userId: string) {
    let found = await this.userModel.findOne({
      where: { userId },
      select: [
        'id',
        'userId',
        'fullName',
        'email',
        'phone',
        'profilePicture',
        'isEnabled',
        'role',
      ],
    });

    if (!found) {
      throw new NotFoundException('User with that userId not found');
    }
  }
}
