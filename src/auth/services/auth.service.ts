import { Injectable } from '@nestjs/common';
import { 
    SignUpCommand,
    InitiateAuthCommand,
    ConfirmSignUpCommand,
    ForgotPasswordCommand,
    ConfirmForgotPasswordCommand,
    CognitoIdentityProviderClient,
    AuthFlowType,
    RespondToAuthChallengeCommand,
    ChallengeNameType,
    AttributeType,
    AdminCreateUserCommand,
    AdminSetUserPasswordCommand,
    DeliveryMediumType,
    ResendConfirmationCodeCommand,
    AdminGetUserCommand,
    AdminConfirmSignUpCommand
} from '@aws-sdk/client-cognito-identity-provider';
import { generateSecretHash } from './cognito/cognito-hash.service';
import { AuthStep, CognitoResponse } from '../interfaces/auth.interface';
import { createHash } from 'crypto';

@Injectable()
export class AuthService {
    private cognitoClient: CognitoIdentityProviderClient;

    constructor() {
        if (!process.env.AWS_ACCESS_KEY_ID || !process.env.AWS_SECRET_ACCESS_KEY) {
            throw new Error('AWS credentials are not configured. Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables.');
        }

        this.cognitoClient = new CognitoIdentityProviderClient({
            region: process.env.AWS_REGION || 'sa-east-1',
            credentials: {
                accessKeyId: process.env.AWS_ACCESS_KEY_ID,
                secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
            }
        });
    }

    private getSecretHash(username: string): string {
        return generateSecretHash(
            username,
            String(process.env.COGNITO_CLIENT_ID),
            String(process.env.COGNITO_CLIENT_SECRET)
        );
    }

    private generateUsernameFromEmail(email: string): string {
        // Gera um hash do email e pega os primeiros 8 caracteres
        const hash = createHash('md5').update(email).digest('hex').substring(0, 8);
        // Remove caracteres especiais do email e adiciona o hash
        const username = `user_${email.split('@')[0].replace(/[^a-zA-Z0-9]/g, '')}_${hash}`;
        return username.toLowerCase();
    }

    private mapChallengeToStep(challengeName?: string): AuthStep {
        switch (challengeName) {
            case ChallengeNameType.NEW_PASSWORD_REQUIRED:
                return 'NEW_PASSWORD_REQUIRED';
            case ChallengeNameType.SMS_MFA:
                return 'SMS_MFA';
            case ChallengeNameType.SOFTWARE_TOKEN_MFA:
                return 'SOFTWARE_TOKEN_MFA';
            default:
                return 'DONE';
        }
    }

    async register(
        email: string,
        password: string, 
        nickname: string,
        name: string,
        address: string,
        birthdate: string,
        gender: string,
        phone_number: string
    ): Promise<CognitoResponse> {
        try {
            const username = this.generateUsernameFromEmail(email);
            const secretHash = this.getSecretHash(username);
            const userAttributes: AttributeType[] = [
                { Name: "email", Value: email },
                { Name: "name", Value: name },
                { Name: "nickname", Value: nickname },
                { Name: "address", Value: address },
                { Name: "birthdate", Value: birthdate },
                { Name: "gender", Value: gender },
                { Name: "phone_number", Value: phone_number }
            ];

            const command = new SignUpCommand({
                ClientId: process.env.COGNITO_CLIENT_ID,
                Username: username,
                Password: password,
                SecretHash: secretHash,
                UserAttributes: userAttributes
            });

            const result = await this.cognitoClient.send(command);

            // Tenta confirmar o usuário automaticamente
            try {
                const confirmCommand = new AdminConfirmSignUpCommand({
                    UserPoolId: process.env.COGNITO_USER_POOL_ID,
                    Username: username
                });

                await this.cognitoClient.send(confirmCommand);
                
                return {
                    statusCode: 200,
                    data: {
                        step: 'SMS_MFA',
                        userId: result.UserSub,
                        email: email,
                        userConfirmed: true,
                        codeDeliveryDetails: result.CodeDeliveryDetails
                    }
                };
            } catch (confirmError) {
                // Se não conseguir confirmar automaticamente, retorna normalmente para confirmação manual
                console.error('Failed to auto-confirm user:', confirmError);
                return {
                    statusCode: 200,
                    data: {
                        step: 'SMS_MFA',
                        userId: result.UserSub,
                        email: email,
                        userConfirmed: result.UserConfirmed,
                        codeDeliveryDetails: result.CodeDeliveryDetails
                    }
                };
            }
        } catch (error: any) {
            if (error.name === 'UsernameExistsException') {
                return {
                    statusCode: 409,
                    error: 'Email already exists'
                };
            }
            
            return {
                statusCode: 400,
                error: error.message
            };
        }
    }

    async adminCreateUser(
        email: string,
        password: string, 
        nickname: string,
        name: string,
        address: string,
        birthdate: string,
        gender: string,
        phone_number: string
    ): Promise<CognitoResponse> {
        try {
            const username = this.generateUsernameFromEmail(email);
            const userAttributes: AttributeType[] = [
                { Name: "email", Value: email },
                { Name: "name", Value: name },
                { Name: "nickname", Value: nickname },
                { Name: "address", Value: address },
                { Name: "birthdate", Value: birthdate },
                { Name: "gender", Value: gender },
                { Name: "phone_number", Value: phone_number }
            ];

            const command = new AdminCreateUserCommand({
                UserPoolId: process.env.COGNITO_USER_POOL_ID,
                Username: username,
                UserAttributes: userAttributes,
                TemporaryPassword: password,
                DesiredDeliveryMediums: [DeliveryMediumType.SMS],
                MessageAction: "SUPPRESS"
            });

            const result = await this.cognitoClient.send(command);

            // Define a senha permanente
            if (result.User) {
                const setPasswordCommand = new AdminSetUserPasswordCommand({
                    UserPoolId: process.env.COGNITO_USER_POOL_ID,
                    Username: username,
                    Password: password,
                    Permanent: true
                });

                await this.cognitoClient.send(setPasswordCommand);
            }
            
            return {
                statusCode: 200,
                data: {
                    step: 'SMS_MFA',
                    userId: result.User?.Username,
                    email: email,
                    userConfirmed: true,
                    codeDeliveryDetails: {
                        AttributeName: "phone_number",
                        DeliveryMedium: "SMS",
                        Destination: phone_number
                    }
                }
            };
        } catch (error: any) {
            if (error.name === 'UsernameExistsException') {
                return {
                    statusCode: 409,
                    error: 'Email already exists'
                };
            }
            
            return {
                statusCode: 400,
                error: error.message
            };
        }
    }

    async login(email: string, password: string): Promise<CognitoResponse> {
        try {
            // No login, permitimos usar tanto o username gerado quanto o email
            const username = email.includes('@') ? this.generateUsernameFromEmail(email) : email;
            const secretHash = this.getSecretHash(username);
            const command = new InitiateAuthCommand({
                ClientId: process.env.COGNITO_CLIENT_ID,
                AuthFlow: AuthFlowType.USER_PASSWORD_AUTH,
                AuthParameters: {
                    USERNAME: username,
                    PASSWORD: password,
                    SECRET_HASH: secretHash
                },
            });

            const result = await this.cognitoClient.send(command);
           
            const step = this.mapChallengeToStep(result.ChallengeName);

            if (step !== 'DONE') {
                return {
                    statusCode: 200,
                    data: {
                        step,
                        session: result.Session,
                        challengeParameters: result.ChallengeParameters
                    }
                };
            }

            if (!result.AuthenticationResult) {
                return {
                    statusCode: 401,
                    error: 'Authentication failed'
                };
            }

            return {
                statusCode: 200,
                data: {
                    step: 'DONE',
                    accessToken: result.AuthenticationResult.AccessToken,
                    refreshToken: result.AuthenticationResult.RefreshToken,
                    expiresIn: result.AuthenticationResult.ExpiresIn,
                    tokenType: result.AuthenticationResult.TokenType
                }
            };
        } catch (error: any) {
            if (error.name === 'NotAuthorizedException') {
                return {
                    statusCode: 401,
                    error: 'Invalid credentials'
                };
            }
            if (error.name === 'UserNotConfirmedException') {
                return {
                    statusCode: 403,
                    error: 'User is not confirmed'
                };
            }
            return {
                statusCode: 400,
                error: error.message
            };
        }
    }

    async respondToChallenge(email: string, session: string, challengeResponse: any): Promise<CognitoResponse> {
        try {
            const username = this.generateUsernameFromEmail(email);
            const secretHash = this.getSecretHash(username);
            const command = new RespondToAuthChallengeCommand({
                ClientId: process.env.COGNITO_CLIENT_ID,
                ChallengeName: ChallengeNameType.SMS_MFA,
                Session: session,
                ChallengeResponses: {
                    USERNAME: username,
                    SMS_MFA_CODE: challengeResponse.code,
                    SECRET_HASH: secretHash
                }
            });

            const result = await this.cognitoClient.send(command);
            const step = this.mapChallengeToStep(result.ChallengeName);

            if (step !== 'DONE') {
                return {
                    statusCode: 200,
                    data: {
                        step,
                        session: result.Session,
                        challengeParameters: result.ChallengeParameters
                    }
                };
            }

            if (!result.AuthenticationResult) {
                return {
                    statusCode: 401,
                    error: 'Challenge response failed'
                };
            }

            return {
                statusCode: 200,
                data: {
                    step: 'DONE',
                    accessToken: result.AuthenticationResult.AccessToken,
                    refreshToken: result.AuthenticationResult.RefreshToken,
                    expiresIn: result.AuthenticationResult.ExpiresIn,
                    tokenType: result.AuthenticationResult.TokenType
                }
            };
        } catch (error: any) {
            if (error.name === 'CodeMismatchException') {
                return {
                    statusCode: 400,
                    error: 'Invalid verification code'
                };
            }
            return {
                statusCode: 400,
                error: error.message
            };
        }
    }

    async confirm(email: string, code: string): Promise<CognitoResponse> {
        const username = this.generateUsernameFromEmail(email);
        try {
            let isAlreadyConfirmed = false;

            try {
                const getUserCommand = new AdminGetUserCommand({
                    UserPoolId: process.env.COGNITO_USER_POOL_ID,
                    Username: username
                });

                const userInfo = await this.cognitoClient.send(getUserCommand);
                const userStatus = userInfo.UserStatus;

                if (userStatus === 'CONFIRMED') {
                    isAlreadyConfirmed = true;
                }
            } catch (getUserError) {
                console.error('Failed to get user status:', getUserError);
            }

            if (!isAlreadyConfirmed) {
                try {
                    const adminCommand = new AdminConfirmSignUpCommand({
                        UserPoolId: process.env.COGNITO_USER_POOL_ID,
                        Username: username
                    });

                    await this.cognitoClient.send(adminCommand);
                } catch (adminError) {
                    console.error('Failed to confirm as admin:', adminError);
                    const secretHash = this.getSecretHash(username);
                    const command = new ConfirmSignUpCommand({
                        ClientId: process.env.COGNITO_CLIENT_ID,
                        Username: username,
                        ConfirmationCode: code,
                        SecretHash: secretHash
                    });

                    await this.cognitoClient.send(command);
                }
            }

            return {
                statusCode: 200,
                data: {
                    step: 'DONE',
                    email: email,
                    message: isAlreadyConfirmed 
                        ? 'User was already confirmed'
                        : 'User confirmed successfully'
                }
            };
        } catch (error: any) {
            if (error.name === 'CodeMismatchException') {
                return {
                    statusCode: 400,
                    error: 'Invalid verification code'
                };
            }
            if (error.name === 'ExpiredCodeException') {
                return {
                    statusCode: 400,
                    error: 'Verification code has expired'
                };
            }
            if (error.name === 'NotAuthorizedException' && error.message.includes('Current status is CONFIRMED')) {
                return {
                    statusCode: 200,
                    data: {
                        step: 'DONE',
                        email: email,
                        message: 'User was already confirmed'
                    }
                };
            }
            return {
                statusCode: 400,
                error: error.message
            };
        }
    }

    async forgotPassword(email: string): Promise<CognitoResponse> {
        try {
            const username = this.generateUsernameFromEmail(email);
            const secretHash = this.getSecretHash(username);
            const command = new ForgotPasswordCommand({
                ClientId: process.env.COGNITO_CLIENT_ID,
                Username: username,
                SecretHash: secretHash
            });

            const result = await this.cognitoClient.send(command);
            
            return {
                statusCode: 200,
                data: {
                    step: 'SMS_MFA',
                    message: 'Reset password code sent',
                    codeDeliveryDetails: result.CodeDeliveryDetails
                }
            };
        } catch (error: any) {
            if (error.name === 'UserNotFoundException') {
                return {
                    statusCode: 404,
                    error: 'User not found'
                };
            }
            return {
                statusCode: 400,
                error: error.message
            };
        }
    }

    async resetPassword(email: string, code: string, newPassword: string): Promise<CognitoResponse> {
        try {
            const username = this.generateUsernameFromEmail(email);
            const secretHash = this.getSecretHash(username);
            const command = new ConfirmForgotPasswordCommand({
                ClientId: process.env.COGNITO_CLIENT_ID,
                Username: username,
                ConfirmationCode: code,
                Password: newPassword,
                SecretHash: secretHash
            });

            await this.cognitoClient.send(command);
            
            return {
                statusCode: 200,
                data: {
                    step: 'DONE',
                    message: 'Password reset successfully'
                }
            };
        } catch (error: any) {
            if (error.name === 'CodeMismatchException') {
                return {
                    statusCode: 400,
                    error: 'Invalid verification code'
                };
            }
            if (error.name === 'ExpiredCodeException') {
                return {
                    statusCode: 400,
                    error: 'Verification code has expired'
                };
            }
            return {
                statusCode: 400,
                error: error.message
            };
        }
    }

    async refresh(refreshToken: string): Promise<CognitoResponse> {
      
        try {
            const command = new InitiateAuthCommand({
                ClientId: process.env.COGNITO_CLIENT_ID,
                AuthFlow: AuthFlowType.REFRESH_TOKEN_AUTH,
                AuthParameters: {
                    REFRESH_TOKEN: refreshToken
                },
            });

            const result = await this.cognitoClient.send(command);

            if (!result.AuthenticationResult) {
                return {
                    statusCode: 401,
                    error: 'Invalid refresh token'
                };
            }

            return {
                statusCode: 200,
                data: {
                    step: 'DONE',
                    accessToken: result.AuthenticationResult.AccessToken,
                    expiresIn: result.AuthenticationResult.ExpiresIn,
                    tokenType: result.AuthenticationResult.TokenType
                }
            };
        } catch (error: any) {
            if (error.name === 'NotAuthorizedException') {
                return {
                    statusCode: 401,
                    error: 'Token has expired or is invalid'
                };
            }
            return {
                statusCode: 400,
                error: error.message
            };
        }
    }

    async resendConfirmationCode(email: string): Promise<CognitoResponse> {
        try {
            const username = this.generateUsernameFromEmail(email);
            const secretHash = this.getSecretHash(username);
            const command = new ResendConfirmationCodeCommand({
                ClientId: process.env.COGNITO_CLIENT_ID,
                Username: username,
                SecretHash: secretHash
            });

            const result = await this.cognitoClient.send(command);
            
            return {
                statusCode: 200,
                data: {
                    step: 'SMS_MFA',
                    email: email,
                    message: 'Confirmation code resent successfully',
                    codeDeliveryDetails: result.CodeDeliveryDetails
                }
            };
        } catch (error: any) {
            if (error.name === 'UserNotFoundException') {
                return {
                    statusCode: 404,
                    error: 'User not found'
                };
            }
            if (error.name === 'InvalidParameterException') {
                return {
                    statusCode: 400,
                    error: 'Invalid email format'
                };
            }
            if (error.name === 'LimitExceededException') {
                return {
                    statusCode: 429,
                    error: 'Too many attempts. Please try again later'
                };
            }
            return {
                statusCode: 400,
                error: error.message
            };
        }
    }
} 