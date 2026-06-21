import 'dotenv/config';
import {
    CognitoIdentityProviderClient,
    CreateUserPoolCommand,
    CreateUserPoolClientCommand,
    CreateUserPoolDomainCommand,
    CreateGroupCommand,
} from '@aws-sdk/client-cognito-identity-provider';

const REGION = process.env.AWS_REGION || 'sa-east-1';
const CALLBACK = 'http://localhost:3001/api/auth/callback/cognito';
const LOGOUT = 'http://localhost:3001';
const GROUPS = ['colaboradores', 'vendas', 'financeiro', 'admin'];

async function main() {
    const domainPrefix = process.argv[2];
    if (!domainPrefix) {
        console.error('Uso: npm run seed:pool -- <prefixo-do-dominio>  (ex.: nestle-sso)');
        process.exit(1);
    }

    const client = new CognitoIdentityProviderClient({
        region: REGION,
        credentials: {
            accessKeyId: String(process.env.AWS_ACCESS_KEY_ID),
            secretAccessKey: String(process.env.AWS_SECRET_ACCESS_KEY),
        },
    });

    console.log('• Criando User Pool (login por e-mail)...');
    const pool = await client.send(new CreateUserPoolCommand({
        PoolName: 'sso-auth-api-email',
        UsernameAttributes: ['email'],
        AutoVerifiedAttributes: ['email'],
        MfaConfiguration: 'OFF',
        Policies: {
            PasswordPolicy: {
                MinimumLength: 8,
                RequireUppercase: true,
                RequireLowercase: true,
                RequireNumbers: true,
                RequireSymbols: true,
            },
        },
    }));
    const userPoolId = pool.UserPool!.Id!;
    console.log(`  ✓ User Pool: ${userPoolId}`);

    console.log('• Criando App Client (secret + Hosted UI)...');
    const appClient = await client.send(new CreateUserPoolClientCommand({
        UserPoolId: userPoolId,
        ClientName: 'portal-sso',
        GenerateSecret: true,
        ExplicitAuthFlows: [
            'ALLOW_USER_PASSWORD_AUTH',
            'ALLOW_REFRESH_TOKEN_AUTH',
        ],
        AllowedOAuthFlowsUserPoolClient: true,
        AllowedOAuthFlows: ['code'],
        AllowedOAuthScopes: ['openid', 'email', 'profile'],
        CallbackURLs: [CALLBACK],
        LogoutURLs: [LOGOUT],
        SupportedIdentityProviders: ['COGNITO'],
    }));
    const clientId = appClient.UserPoolClient!.ClientId!;
    const clientSecret = appClient.UserPoolClient!.ClientSecret!;
    console.log(`  ✓ App Client: ${clientId}`);

    console.log('• Criando domínio do Hosted UI...');
    await client.send(new CreateUserPoolDomainCommand({
        UserPoolId: userPoolId,
        Domain: domainPrefix,
    }));
    const domain = `https://${domainPrefix}.auth.${REGION}.amazoncognito.com`;
    console.log(`  ✓ Domínio: ${domain}`);

    console.log('• Criando grupos...');
    for (const GroupName of GROUPS) {
        await client.send(new CreateGroupCommand({ UserPoolId: userPoolId, GroupName }));
        console.log(`  ✓ Grupo: ${GroupName}`);
    }

    const issuer = `https://cognito-idp.${REGION}.amazonaws.com/${userPoolId}`;
    console.log('\n========================================================');
    console.log(' COLE NO  sso-auth-api/.env :');
    console.log('========================================================');
    console.log(`COGNITO_USER_POOL_ID=${userPoolId}`);
    console.log(`COGNITO_CLIENT_ID=${clientId}`);
    console.log(`COGNITO_CLIENT_SECRET=${clientSecret}`);
    console.log(`COGNITO_DOMAIN=${domain}`);
    console.log(`COGNITO_ALLOWED_CLIENT_IDS=${clientId}`);
    console.log('\n========================================================');
    console.log(' COLE NO  portal-sso/.env.local :');
    console.log('========================================================');
    console.log(`AUTH_COGNITO_ID=${clientId}`);
    console.log(`AUTH_COGNITO_SECRET=${clientSecret}`);
    console.log(`AUTH_COGNITO_ISSUER=${issuer}`);
    console.log('\n✓ Pool pronto. Atualize os .env, reinicie os dois apps e crie um usuário novo.');
}

main().catch((err) => {
    console.error('Erro no setup:', err.name, '-', err.message);
    process.exit(1);
});
