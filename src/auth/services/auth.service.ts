import { Injectable } from '@nestjs/common';
import {
    SignUpCommand,
    InitiateAuthCommand,
    ConfirmSignUpCommand,
    ForgotPasswordCommand,
    ConfirmForgotPasswordCommand,
    CognitoIdentityProviderClient,
    AuthFlowType,
    ChallengeNameType,
    AttributeType,
    AdminCreateUserCommand,
    ResendConfirmationCodeCommand,
    AdminAddUserToGroupCommand,
    AdminRemoveUserFromGroupCommand,
    CreateGroupCommand,
    ListUsersInGroupCommand
} from '@aws-sdk/client-cognito-identity-provider';
import { generateSecretHash } from './cognito/cognito-hash.service';
import { AuthStep, CognitoResponse } from '../interfaces/auth.interface';
import { handleCognitoError } from '../errors/cognito-error.map';

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

    private cognitoUsername(email: string): string {
        return email.trim().toLowerCase();
    }

    private mapChallengeToStep(challengeName?: string): AuthStep {
        switch (challengeName) {
            case ChallengeNameType.NEW_PASSWORD_REQUIRED:
                return 'NEW_PASSWORD_REQUIRED';
            default:
                return 'DONE';
        }
    }

    async register(
        email: string,
        password: string,
        name: string,
        nickname: string,
        address: string,
        birthdate: string,
        gender: string,
        phone_number: string
    ): Promise<CognitoResponse> {
        try {
            const username = this.cognitoUsername(email);
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

            const defaultGroup = process.env.COGNITO_DEFAULT_GROUP;
            if (defaultGroup) {
                try {
                    await this.cognitoClient.send(new AdminAddUserToGroupCommand({
                        UserPoolId: process.env.COGNITO_USER_POOL_ID,
                        Username: username,
                        GroupName: defaultGroup
                    }));
                } catch {
                }
            }

            return {
                statusCode: 200,
                data: {
                    step: 'CONFIRM_SIGN_UP',
                    userId: result.UserSub,
                    email: email,
                    userConfirmed: result.UserConfirmed,
                    codeDeliveryDetails: result.CodeDeliveryDetails
                }
            };
        } catch (error: any) {
            return handleCognitoError(error);
        }
    }

    async adminCreateUser(
        email: string,
        name: string,
        group?: string
    ): Promise<CognitoResponse> {
        try {
            const username = this.cognitoUsername(email);

            await this.cognitoClient.send(new AdminCreateUserCommand({
                UserPoolId: process.env.COGNITO_USER_POOL_ID,
                Username: username,
                UserAttributes: [
                    { Name: 'email', Value: email },
                    { Name: 'email_verified', Value: 'true' },
                    { Name: 'name', Value: name }
                ],
                DesiredDeliveryMediums: ['EMAIL']
            }));

            if (group) {
                await this.cognitoClient.send(new AdminAddUserToGroupCommand({
                    UserPoolId: process.env.COGNITO_USER_POOL_ID,
                    Username: username,
                    GroupName: group
                }));
            }

            return {
                statusCode: 200,
                data: {
                    step: 'DONE',
                    email,
                    message: `Convite enviado para ${email}${group ? ` (setor '${group}')` : ''}.`
                }
            };
        } catch (error: any) {
            return handleCognitoError(error);
        }
    }

    async login(email: string, password: string): Promise<CognitoResponse> {
        try {
            const username = email.includes('@') ? this.cognitoUsername(email) : email;
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
            return handleCognitoError(error);
        }
    }

    async confirm(email: string, code: string): Promise<CognitoResponse> {
        try {
            const username = this.cognitoUsername(email);
            const secretHash = this.getSecretHash(username);

            const command = new ConfirmSignUpCommand({
                ClientId: process.env.COGNITO_CLIENT_ID,
                Username: username,
                ConfirmationCode: code,
                SecretHash: secretHash
            });

            await this.cognitoClient.send(command);

            return {
                statusCode: 200,
                data: {
                    step: 'DONE',
                    email: email,
                    message: 'User confirmed successfully'
                }
            };
        } catch (error: any) {
            return handleCognitoError(error);
        }
    }

    async forgotPassword(email: string): Promise<CognitoResponse> {
        try {
            const username = this.cognitoUsername(email);
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
                    step: 'RESET_CODE_SENT',
                    message: 'Reset password code sent',
                    codeDeliveryDetails: result.CodeDeliveryDetails
                }
            };
        } catch (error: any) {
            return handleCognitoError(error);
        }
    }

    async resetPassword(email: string, code: string, newPassword: string): Promise<CognitoResponse> {
        try {
            const username = this.cognitoUsername(email);
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
            return handleCognitoError(error);
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
            return handleCognitoError(error);
        }
    }

    async resendConfirmationCode(email: string): Promise<CognitoResponse> {
        try {
            const username = this.cognitoUsername(email);
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
                    step: 'CONFIRM_SIGN_UP',
                    email: email,
                    message: 'Confirmation code resent successfully',
                    codeDeliveryDetails: result.CodeDeliveryDetails
                }
            };
        } catch (error: any) {
            return handleCognitoError(error);
        }
    }

    async createGroup(name: string, description?: string): Promise<CognitoResponse> {
        try {
            await this.cognitoClient.send(new CreateGroupCommand({
                UserPoolId: process.env.COGNITO_USER_POOL_ID,
                GroupName: name,
                Description: description
            }));

            return {
                statusCode: 200,
                data: { step: 'DONE', message: `Grupo '${name}' criado com sucesso` }
            };
        } catch (error: any) {
            return handleCognitoError(error);
        }
    }

    async addUserToGroup(email: string, group: string): Promise<CognitoResponse> {
        try {
            const username = this.cognitoUsername(email);
            await this.cognitoClient.send(new AdminAddUserToGroupCommand({
                UserPoolId: process.env.COGNITO_USER_POOL_ID,
                Username: username,
                GroupName: group
            }));

            return {
                statusCode: 200,
                data: { step: 'DONE', email, message: `Usuário adicionado ao grupo '${group}'` }
            };
        } catch (error: any) {
            return handleCognitoError(error);
        }
    }

    async removeUserFromGroup(email: string, group: string): Promise<CognitoResponse> {
        try {
            const username = this.cognitoUsername(email);
            await this.cognitoClient.send(new AdminRemoveUserFromGroupCommand({
                UserPoolId: process.env.COGNITO_USER_POOL_ID,
                Username: username,
                GroupName: group
            }));

            return {
                statusCode: 200,
                data: { step: 'DONE', email, message: `Usuário removido do grupo '${group}'` }
            };
        } catch (error: any) {
            return handleCognitoError(error);
        }
    }

    async listUsersInGroup(group: string): Promise<CognitoResponse> {
        try {
            const result = await this.cognitoClient.send(new ListUsersInGroupCommand({
                UserPoolId: process.env.COGNITO_USER_POOL_ID,
                GroupName: group
            }));

            const users = (result.Users ?? []).map((u) => ({
                username: u.Username,
                status: u.UserStatus,
                email: u.Attributes?.find((a) => a.Name === 'email')?.Value
            }));

            return {
                statusCode: 200,
                data: { step: 'DONE', message: `${users.length} usuário(s) no grupo '${group}'`, users } as any
            };
        } catch (error: any) {
            return handleCognitoError(error);
        }
    }
} 