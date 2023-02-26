import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document } from 'mongoose';

@Schema({
  timestamps: true,
})
export class User extends Document {
  @Prop()
  name: string;

  @Prop({ unique: [true, 'Duplicate email entered'] })
  email: string;

  @Prop({ unique: [true, 'Duplicate phone entered'] })
  phone: string;

  @Prop({ type: mongoose.Schema.Types.Boolean, default: false })
  emailVerified: boolean;

  @Prop({ type: mongoose.Schema.Types.Boolean, default: false })
  phoneVerified: boolean;

  @Prop()
  password: string;
}

export const UserSchema = SchemaFactory.createForClass(User);
