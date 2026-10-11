import { Body, Controller, Delete, Param, Post, Get, Query, Req, UseGuards, UploadedFile, UseInterceptors } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { FileInterceptor } from '@nestjs/platform-express';
import { DbService } from './db.service';
import { CreateNoteDto } from './dto';

@Controller('notes')
@UseGuards(AuthGuard('jwt'))
export class NotesController {
  constructor(private readonly db: DbService) {}

  @Post()
  create(@Body() body: CreateNoteDto, @Req() req: any) {
    return this.db.query('INSERT INTO notes (title, owner_id) VALUES ($1, $2)', [body.title, req.user.id]);
  }

  @Get('export')
  exportAll(@Req() req: any) {
    return this.db.query('SELECT id, email FROM users WHERE id = $1', [req.user.id]);
  }

  @Delete(':id')
  remove(@Param('id') id: string, @Req() req: any) {
    return this.db.query('DELETE FROM notes WHERE id = $1 AND owner_id = $2', [id, req.user.id]);
  }

  @Get()
  list(@Query('limit') limit: string, @Req() req: any) {
    const capped = Math.min(Number(limit), 100);
    return this.db.query('SELECT id, title FROM notes WHERE owner_id = $1 LIMIT $2', [req.user.id, capped]);
  }

  @Post('upload')
  @UseInterceptors(FileInterceptor('file', { limits: { fileSize: 5 * 1024 * 1024 }, fileFilter: (req, file, cb) => cb(null, ['image/png', 'image/jpeg'].includes(file.mimetype)) }))
  upload(@UploadedFile() file: any) {
    return { size: file.size };
  }
}
