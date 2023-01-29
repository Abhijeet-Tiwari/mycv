import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { promisify } from 'util';
import { randomBytes, scrypt as _script } from 'crypto';
import { UsersService } from './users.service';

const scrypt = promisify(_script);

@Injectable()
export class AuthService {
  constructor(private usersService: UsersService) {}

  async signup(email: string, password: string) {
    // See if email is in use
    const users = await this.usersService.find(email);
    if (users.length) {
      throw new BadRequestException('Email already taken');
    }
    // Hash the user's password
    // 1. Generate a salt
    const salt = randomBytes(8).toString('hex');

    // 2. Hash the salt and password together
    const hash = (await scrypt(password, salt, 32)) as Buffer;

    // 3. Join the hashed result
    const result = salt + '.' + hash.toString('hex');

    // Create a user and save it
    const user = this.usersService.create(email, result);

    // return the user
    return user;
  }

  async signin(email: string, password: string) {
    const [user] = await this.usersService.find(email);
    if (!user) {
      throw new NotFoundException('User Not found!');
    }

    const [salt, storedHash] = user.password.split('.');
    const hash = (await scrypt(password, salt, 32)) as Buffer;
    
    if (storedHash !== hash.toString('hex')) {
      throw new BadRequestException('Invalid Password');
    }
    return user;
  }
}
