import { Injectable, Logger, UnauthorizedException } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { Model } from "mongoose";
import * as bcrypt from "bcryptjs";
import { JwtService } from "@nestjs/jwt";
import { User } from "../users/user.schema";

@Injectable()
export class AuthService {
    private readonly logger = new Logger(AuthService.name);

    constructor(
        @InjectModel(User.name) private userModel: Model<User>,
        private jwtService: JwtService,
    ) {}

    

    async register(email: string, firstName: string, lastName: string, password: string) {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new this.userModel({ email, firstName, lastName, password: hashedPassword });
        this.logger.log(`New user created: ${email}`);
        return newUser.save();
    }

    async login(email: string, password: string) {
        const user = await this.userModel.findOne({ email });
        if (!user) {
            this.logger.warn(`Login failed: User not found: ${email}`);
            throw new UnauthorizedException("Invalid credentials");
        }
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            this.logger.warn(`Login failed: Invalid password for ${email}`);
            throw new UnauthorizedException("Invalid credentials");
        }

        const accessToken = this.jwtService.sign({ email }, { expiresIn: '1h' });
        const refreshToken = this.jwtService.sign({ email }, { expiresIn: '7d' });
        
        // Optionally, save the refresh token in the database
        user.refreshToken = refreshToken;
        await user.save();

        this.logger.log(`User logged in: ${email}`);
        return { accessToken, refreshToken };

    }

    async refreshToken(oldRefreshToken: string) {
        try {
          const decoded = this.jwtService.verify(oldRefreshToken);
          const email = decoded.email;
          const user = await this.userModel.findOne({ email });
          if (!user) {
            this.logger.warn(`Refresh token failed: User not found (${email})`);
            throw new UnauthorizedException("Invalid refresh token");
          }
          if (user.refreshToken !== oldRefreshToken) {
            this.logger.warn(`Refresh token mismatch for ${email}`);
            throw new UnauthorizedException("Invalid refresh token");
          }
          // Generate new tokens
          const newAccessToken = this.jwtService.sign({ email }, { expiresIn: '1h' });
          const newRefreshToken = this.jwtService.sign({ email }, { expiresIn: '7d' });
          
          // Update stored refresh token
          user.refreshToken = newRefreshToken;
          await user.save();
    
          this.logger.log(`Refresh token issued for ${email}`);
          return { accessToken: newAccessToken, refreshToken: newRefreshToken };
        } catch (error) {
          this.logger.error('Error refreshing token', error.stack);
          throw new UnauthorizedException("Invalid refresh token");
        }
      }
}
