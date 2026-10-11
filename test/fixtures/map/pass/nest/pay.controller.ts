import { BadRequestException, Body, Controller, Headers, Post } from '@nestjs/common';
import { DbService } from './db.service';
import { verifySignature } from './pay';

@Controller('webhooks/pay')
export class PayController {
  constructor(private readonly db: DbService) {}

  @Post()
  handle(@Body() body: any, @Headers('x-pay-signature') sig: string) {
    const ok = verifySignature(JSON.stringify(body), sig);
    if (!ok) throw new BadRequestException('bad signature');
    return this.db.query('UPDATE accounts SET paid = 1 WHERE id = $1', [body.account]);
  }
}
