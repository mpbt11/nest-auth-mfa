import 'dotenv/config';
import {
    CognitoIdentityProviderClient,
    CreateGroupCommand,
    AdminAddUserToGroupCommand,
} from '@aws-sdk/client-cognito-identity-provider';

function cognitoUsername(email: string): string {
    return email.trim().toLowerCase();
}

async function main() {
    const email = process.argv[2];
    if (!email) {
        console.error('Uso: npm run seed:admin -- usuario@exemplo.com');
        process.exit(1);
    }

    const client = new CognitoIdentityProviderClient({
        region: process.env.AWS_REGION || 'sa-east-1',
        credentials: {
            accessKeyId: String(process.env.AWS_ACCESS_KEY_ID),
            secretAccessKey: String(process.env.AWS_SECRET_ACCESS_KEY),
        },
    });

    const UserPoolId = process.env.COGNITO_USER_POOL_ID;
    const GroupName = 'admin';

    try {
        await client.send(new CreateGroupCommand({ UserPoolId, GroupName }));
        console.log(`✓ Grupo '${GroupName}' criado.`);
    } catch (err: any) {
        if (err.name === 'GroupExistsException') {
            console.log(`• Grupo '${GroupName}' já existe.`);
        } else {
            throw err;
        }
    }

    const Username = cognitoUsername(email);
    await client.send(
        new AdminAddUserToGroupCommand({ UserPoolId, Username, GroupName }),
    );
    console.log(`✓ ${email} agora é admin. Faça logout/login para atualizar o token.`);
}

main().catch((err) => {
    console.error('Erro no seed:', err.message);
    process.exit(1);
});
