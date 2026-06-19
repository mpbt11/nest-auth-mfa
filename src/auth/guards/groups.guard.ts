import {
    CanActivate,
    ExecutionContext,
    ForbiddenException,
    Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';
import { GROUPS_KEY } from '../decorators/groups.decorator';

@Injectable()
export class GroupsGuard implements CanActivate {
    constructor(private readonly reflector: Reflector) {}

    canActivate(context: ExecutionContext): boolean {
        const requiredGroups = this.reflector.getAllAndOverride<string[]>(
            GROUPS_KEY,
            [context.getHandler(), context.getClass()],
        );

        if (!requiredGroups || requiredGroups.length === 0) {
            return true;
        }

        const request = context.switchToHttp().getRequest<Request>();
        const userGroups: string[] =
            (request as any).user?.['cognito:groups'] ?? [];

        const allowed = requiredGroups.some((g) => userGroups.includes(g));
        if (!allowed) {
            throw new ForbiddenException(
                'Acesso negado: você não pertence a um grupo autorizado para este recurso.',
            );
        }

        return true;
    }
}
