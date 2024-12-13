import { HttpStatus, Injectable } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { Repository } from "typeorm";
import { User } from "./entities/user";
import { RegisterUserDto } from "./dto/register-user.dto/register-user.dto";
import { LoginUserDto } from "./dto/login-user.dto/login-user.dto";
import * as bcrypt from "bcryptjs";
import { JwtService } from "@nestjs/jwt";
import { RpcException } from "@nestjs/microservices";
import { JwtPayload } from "./interfaces/jwt-payload.interface";
import { envs } from "../config";

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly jwtService: JwtService,
  ) {}

  private failedAttempts = new Map<string, { attempts: number; blockExpires: Date | null }>();

  private readonly MAX_ATTEMPTS = 5;
  private readonly BLOCK_TIME_MS = 5 * 60 * 1000; // 5 minutos

  async register(registerUserDto: RegisterUserDto): Promise<String> {
    const { email, password } = registerUserDto;

    const user = await this.userRepository.findOneBy({ email });
    if (user) {
      throw new RpcException({
        status: HttpStatus.CONFLICT,
        message: 'User with this email already exists',
      });
    }
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = this.userRepository.create({ email, password: hashedPassword });
    await this.userRepository.save(newUser);
    return "User registered successfully";
  }

  async login(loginUserDto: LoginUserDto) {
    const { email, password } = loginUserDto;

    // Verificar si el usuario está bloqueado
    const userAttempts = this.failedAttempts.get(email) || { attempts: 0, blockExpires: null };

    if (userAttempts.blockExpires && userAttempts.blockExpires > new Date()) {
      throw new RpcException({
        status: HttpStatus.FORBIDDEN,
        message: `Account blocked due to multiple failed attempts. Please try again in 5 minutes.`,
      });
    }

    const user = await this.userRepository.findOneBy({ email });
    if (!user) {
      this.trackFailedAttempt(email);
      throw new RpcException({
        status: HttpStatus.UNAUTHORIZED,
        message: 'Invalid credentials',
      });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      this.trackFailedAttempt(email);
      throw new RpcException({
        status: HttpStatus.UNAUTHORIZED,
        message: 'Invalid credentials',
      });
    }

    this.resetFailedAttempts(email);

    const payload: JwtPayload = {
      id: user.id,
      email: user.email,
    };

    return {
      token: await this.signJWT(payload),
    };
  }

  async signJWT(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }

  async verifyToken(token: string) {
    try {
      const { sub, iat, exp, ...user } = this.jwtService.verify(token, {
        secret: envs.jwtSecret,
      });

      return {
        user: user,
        token: await this.signJWT(user),
      }
    } catch (error) {
      console.log(error);
      throw new RpcException({
        status: HttpStatus.UNAUTHORIZED,
        message: 'Invalid token'
      })
    }
  }

  private trackFailedAttempt(email: string) {
    const userAttempts = this.failedAttempts.get(email) || { attempts: 0, blockExpires: null };

    userAttempts.attempts += 1;

    if (userAttempts.attempts >= this.MAX_ATTEMPTS) {
      userAttempts.blockExpires = new Date(Date.now() + this.BLOCK_TIME_MS);
    }

    this.failedAttempts.set(email, userAttempts);
  }

  private resetFailedAttempts(email: string) {
    this.failedAttempts.delete(email);
  }
}
