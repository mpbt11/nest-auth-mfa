import { Injectable, NestInterceptor, ExecutionContext, CallHandler } from '@nestjs/common';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { CognitoResponse } from '../interfaces/auth.interface';

@Injectable()
export class ResponseInterceptor implements NestInterceptor {
    intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
        return next.handle().pipe(
            map((response: CognitoResponse) => {
                const httpResponse = context.switchToHttp().getResponse();
                httpResponse.status(response.statusCode);

                if (response.error) {
                    return { error: response.error };
                }

                return response.data;
            })
        );
    }
} 