import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { Request } from 'express';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { GroupsGuard } from '../guards/groups.guard';
import { Groups } from '../decorators/groups.decorator';

@Controller('me')
@UseGuards(JwtAuthGuard)
export class MeController {
    @Get()
    getProfile(@Req() req: Request) {
        const user = (req as any).user;
        return {
            message: 'Token validado com sucesso pelo backend NestJS.',
            sub: user?.sub,
            username: user?.username,
            scope: user?.scope,
            clientId: user?.client_id,
            groups: user?.['cognito:groups'] ?? [],
            claims: user,
        };
    }

    @Get('financeiro')
    @UseGuards(GroupsGuard)
    @Groups('financeiro')
    getFinanceiro(@Req() req: Request) {
        const user = (req as any).user;
        return {
            message: 'Acesso liberado: recurso exclusivo do grupo financeiro.',
            username: user?.username,
            groups: user?.['cognito:groups'] ?? [],
        };
    }
}
