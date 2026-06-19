import {
    CanActivate,
    ExecutionContext,
    Injectable,
    UnauthorizedException,
} from '@nestjs/common';
import { Request } from 'express';
import { CognitoJwtVerifier } from 'aws-jwt-verify';

@Injectable()
export class JwtAuthGuard implements CanActivate {
    private readonly verifier = CognitoJwtVerifier.create({
        userPoolId: String(process.env.COGNITO_USER_POOL_ID),
        tokenUse: 'access',
        clientId: (
            process.env.COGNITO_ALLOWED_CLIENT_IDS ||
            String(process.env.COGNITO_CLIENT_ID)
        )
            .split(',')
            .map((id) => id.trim())
            .filter(Boolean),
    });

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const request = context.switchToHttp().getRequest<Request>();
        const authHeader = request.headers.authorization;

        if (!authHeader?.startsWith('Bearer ')) {
            throw new UnauthorizedException('Token Bearer ausente.');
        }

        const token = authHeader.slice('Bearer '.length).trim();

        try {
            const payload = await this.verifier.verify(token);
            (request as any).user = payload;
            return true;
        } catch {
            throw new UnauthorizedException('Token inválido ou expirado.');
        }
    }
}
