export type AuthStep = 'NEW_PASSWORD_REQUIRED' | 'SMS_MFA' | 'SOFTWARE_TOKEN_MFA' | 'DONE';

export interface AuthResponse {
    step: AuthStep;
    userId?: string;
    email?: string;
    userConfirmed?: boolean;
    session?: string;
    challengeParameters?: Record<string, string>;
    accessToken?: string;
    refreshToken?: string;
    expiresIn?: number;
    tokenType?: string;
    message?: string;
    codeDeliveryDetails?: {
        AttributeName?: string;
        DeliveryMedium?: string;
        Destination?: string;
    };
}

export interface CognitoResponse {
    statusCode: number;
    data?: AuthResponse;
    error?: string;
} 