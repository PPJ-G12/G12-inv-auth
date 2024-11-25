import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthModule } from './auth/auth.module';

@Module({
  imports: [
    TypeOrmModule.forRoot({
      type: 'postgres',
      host: 'localhost', 
      port: 5436, 
      username: 'nest_user', 
      password: 'nest_password',
      database: 'auth_db',
      autoLoadEntities: true,
      synchronize: true, 
    }),
    AuthModule,
  ],
})
export class AppModule {}
