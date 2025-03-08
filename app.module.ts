import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { AuthModule } from 'src/auth/auth.module';

@Module({
  imports: [
    // Replace 'myDatabase' with your actual database name if it's different
    MongooseModule.forRoot('mongodb://localhost:27017/myDatabase', {
      // Optional: additional configuration options
      // useNewUrlParser: true,
      // useUnifiedTopology: true,
    }),
    AuthModule,
  ],
})
export class AppModule {}
