import { Body, Controller, Delete, Param, Post, Get, Query, Req, UseGuards, UploadedFile, UseInterceptors } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { FileInterceptor } from '@nestjs/platform-express';
import { DbService } from './db.service';

@Controller('notes')
export class NotesController {
  constructor(private readonly db: DbService) {}

  @Post()
  create(@Body() body: any) {
    return this.db.query('INSERT INTO notes (title, owner_id) VALUES ($1, $2)', [body.title, body.owner]);
  }

  @Get('export')
  exportAll() {
    return this.db.query('SELECT id, email FROM users', []);
  }

  @Delete(':id')
  @UseGuards(AuthGuard('jwt'))
  remove(@Param('id') id: string) {
    return this.db.query('DELETE FROM notes WHERE id = $1', [id]);
  }

  @Get()
  @UseGuards(AuthGuard('jwt'))
  list(@Query('limit') limit: string, @Req() req: any) {
    return this.db.query('SELECT id, title FROM notes WHERE owner_id = $1 LIMIT $2', [req.user.id, Number(limit)]);
  }

  @Post('upload')
  @UseGuards(AuthGuard('jwt'))
  @UseInterceptors(FileInterceptor('file'))
  upload(@UploadedFile() file: any) {
    return { name: file.originalname };
  }
}
