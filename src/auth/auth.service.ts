import { Injectable, UnauthorizedException } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { Model } from "mongoose";
import * as bcrypt from "bcryptjs";
import { JwtService } from "@nestjs/jwt";
import { User } from "../users/user.schema";

@Injectable()
export class AuthService {
    constructor(
        @InjectModel(User.name) private userModel: Model<User>,
        private jwtService: JwtService,
    ) {}

    async register(email: string, firstName: string, lastName: string, password: string) {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new this.userModel({ email, firstName, lastName, password: hashedPassword });
        return newUser.save();
    }

    async login(email: string, password: string) {
        const user = await this.userModel.findOne({ email });
        if (!user) {
            throw new UnauthorizedException("Invalid credentials");
        }
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            throw new UnauthorizedException("Invalid credentials");
        }
        const token = this.jwtService.sign({ email });
        return { token };
    }
}
