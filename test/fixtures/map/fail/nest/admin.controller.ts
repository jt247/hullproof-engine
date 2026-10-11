import { Body, Controller, Post, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { DbService } from './db.service';

@Controller('admin/users')
@UseGuards(AuthGuard('jwt'))
export class AdminController {
  constructor(private readonly db: DbService) {}

  @Post('role')
  setRole(@Body() body: any) {
    return this.db.query('UPDATE users SET role = $1 WHERE id = $2', [body.role, body.id]);
  }
}
