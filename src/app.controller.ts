import { Controller, Get } from '@nestjs/common';

@Controller()
export class AppController {
  @Get()
  getStatus() {
    return { status: 'ok', service: 'nest-auth-mfa' };
  }
}
