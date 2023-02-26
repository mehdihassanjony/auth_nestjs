import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './schemas/user.schema';
import * as bcrypt from 'bcryptjs';
import { JwtStrategy } from './jwt.strategy';
import { SignUpDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import { UserTokenPayloadDto } from 'src/common/common-dto';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  constructor(
    @InjectModel(User.name)
    private userModel: Model<User>,
    private jwtStrategy: JwtStrategy,
  ) {}

  async signUp(
    signUpDto: SignUpDto,
  ): Promise<{ screen: string; user: object }> {
    const { name, email, phone, password } = signUpDto;

    const userFound = await this.userModel.findOne({ phone: signUpDto.phone });

    // ======== IF USER EXISTS WITH PHONE NUMBER SEND TO OTP SCREEN ========= //
    if (userFound) {
      this.sendSms(userFound.phone, '12345');

      return {
        screen: 'otp',
        user: { _id: userFound._id, phone: userFound.phone },
      };
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await this.userModel.create({
      name,
      email,
      phone,
      password: hashedPassword,
    });

    await this.sendSms(newUser.phone, '1234');

    await this.sendMail(newUser.email, '1234');

    return { screen: 'otp', user: { _id: newUser._id, phone: newUser.phone } };
  }

  async sendSms(phone: string, message: string) {
    this.logger.log(`Successfully sent SMS ${message} to: ${phone}`);
  }

  async matchOtp(phone: string, otp: string) {
    this.logger.log(`Successfully matched otp ${otp} to: ${phone}`);
    return true;
  }

  async sendMail(email: string, message: string) {
    this.logger.log(`Successfully sent mail to: ${email}`);
  }

  async login(loginDto: LoginDto): Promise<{ token: string; screen: string }> {
    const { phone, password } = loginDto;

    const user = await this.userModel.findOne({ phone });

    if (!user) {
      throw new NotFoundException('User with that phone no not found');
    }

    // ========= IF USER'S PHONE NOT VERIFIED THEN SEND TO OTP SCREEN =========== //
    if (!user.phoneVerified) {
      this.sendSms(user.phone, '12345');

      return {
        screen: 'otp',
        token: null,
      };
    }

    if (!user) {
      throw new UnauthorizedException('Invalid email or password');
    }

    const isPasswordMatched = await bcrypt.compare(password, user.password);

    if (!isPasswordMatched) {
      throw new UnauthorizedException('Invalid email or password');
    }

    const token = await this.jwtStrategy.sign({ _id: user._id });

    return { token, screen: 'dashboard' };
  }

  async getUserDetail(_id: string) {
    let found = await this.userModel.findOne({
      where: { _id },
      select: [
        '_id',
        'name',
        'email',
        'phone',
        'emailVerified',
        'phoneVerified',
      ],
    });

    if (!found) {
      throw new NotFoundException('User with that userId not found');
    }

    return found;
  }

  async changePassword(
    tokenPayload: UserTokenPayloadDto,
    body: ChangePasswordDto,
  ) {
    console.log(tokenPayload);
    const user = await this.userModel.findOne({ _id: tokenPayload._id });

    console.log(user);
    if (!(await bcrypt.compare(body.prevPassword, user.password))) {
      throw new BadRequestException('Previous password didn"t match');
    }

    const hashedPassword = await bcrypt.hash(body.newPassword, 10);

    user.password = hashedPassword;

    user.save();

    return {
      _id: user._id,
    };
  }

  async forgotPassword(body: ForgotPasswordDto): Promise<{ screen: string }> {
    const user = await this.userModel.findOne({ phone: body.phone });

    if (!user) {
      throw new NotFoundException('User with that phone not found');
    }

    this.sendSms(user.phone, '1234');

    return { screen: 'otp' };
  }

  async verifyOtp(body: VerifyOtpDto): Promise<{ token: string }> {
    const user = await this.userModel.findOne({ phone: body.phone });

    if (!user) {
      throw new NotFoundException('User with that phone not found');
    }

    // Match OTP from redis
    const otpMatched = await this.matchOtp(user.phone, body.otp);

    if (!otpMatched) {
      throw new BadRequestException('Otp didn"t matched');
    }

    user.phoneVerified = true;

    user.save();

    return {
      token: await this.jwtStrategy.sign({ _id: user._id }),
    };
  }
}
