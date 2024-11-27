import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthModule } from './auth/auth.module';

@Module({
  imports: [
    TypeOrmModule.forRoot({
      type: 'postgres',
      host: 'auth-db', 
      username: 'postgres', 
      password: '123456',
      database: 'authdb',
      autoLoadEntities: true,
      synchronize: true, 
    }),
    AuthModule,
  ],
})
export class AppModule {}
