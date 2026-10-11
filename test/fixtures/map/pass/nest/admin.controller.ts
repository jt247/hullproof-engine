import { Body, Controller, Post, Req, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Roles } from './roles.decorator';
import { RolesGuard } from './roles.guard';
import { DbService } from './db.service';
import { AuditService } from './audit.service';
import { SetRoleDto } from './dto';

@Controller('admin/users')
@UseGuards(AuthGuard('jwt'), RolesGuard)
@Roles('admin')
export class AdminController {
  constructor(private readonly db: DbService, private readonly audit: AuditService) {}

  @Post('role')
  async setRole(@Body() body: SetRoleDto, @Req() req: any) {
    await this.db.query('UPDATE users SET role = $1 WHERE id = $2', [body.role, body.id]);
    this.audit.record({ actor: req.user.id, action: 'set_role', target: body.id });
  }
}
