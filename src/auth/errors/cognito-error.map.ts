interface CognitoErrorResponse {
  statusCode: number;
  error: string;
}

interface CognitoErrorMap {
  [key: string]: CognitoErrorResponse;
}

export const cognitoErrorMap: CognitoErrorMap = {
  UsernameExistsException: {
    statusCode: 409,
    error: 'Email already exists'
  },
  NotAuthorizedException: {
    statusCode: 401,
    error: 'Invalid credentials'
  },
  UserNotConfirmedException: {
    statusCode: 403,
    error: 'User is not confirmed'
  },
  CodeMismatchException: {
    statusCode: 400,
    error: 'Invalid verification code'
  },
  ExpiredCodeException: {
    statusCode: 400,
    error: 'Verification code has expired'
  },
  UserNotFoundException: {
    statusCode: 404,
    error: 'User not found'
  },
  InvalidParameterException: {
    statusCode: 400,
    error: 'Invalid parameters provided'
  },
  LimitExceededException: {
    statusCode: 429,
    error: 'Too many attempts. Please try again later'
  }
};

export const handleCognitoError = (error: any): CognitoErrorResponse => {
  // Caso especial para usuário já confirmado
  if (error.name === 'NotAuthorizedException' && error.message.includes('Current status is CONFIRMED')) {
    return {
      statusCode: 200,
      error: 'User was already confirmed'
    };
  }

  // Busca o erro no mapa ou retorna um erro genérico
  return cognitoErrorMap[error.name] || {
    statusCode: 400,
    error: error.message
  };
}; 