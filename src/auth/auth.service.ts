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

    const user = await this.userRepository.findOneBy({ email });
    if (!user) {
      throw new RpcException({
        status: HttpStatus.UNAUTHORIZED,
        message: 'Invalid credentials',
      });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new RpcException({
        status: HttpStatus.UNAUTHORIZED,
        message: 'Invalid credentials',
      });
    }

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
}
