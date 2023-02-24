export class ResponseDto {
  code: number;
  success: boolean;
  message: string;
  data: any;
}

export class UserTokenPayloadDto {
  _id: string;
  name: string;
  email: string;
  phone: string;
  emailVerified: boolean;
  phoneVerified: boolean;
}
