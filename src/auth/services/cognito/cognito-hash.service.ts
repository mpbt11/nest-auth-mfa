import * as crypto from 'crypto';
 /**
     * Generates a secret hash for Cognito authentication
     * @param username - The username of the user
     * @param clientId - The Cognito app client ID
     * @param clientSecret - The Cognito app client secret
     * @returns The generated secret hash in base64 format
     */
export function generateSecretHash(username: string, clientId: string, clientSecret: string): string {
  return crypto
    .createHmac('sha256', clientSecret)
    .update(username + clientId)
    .digest('base64');
}
