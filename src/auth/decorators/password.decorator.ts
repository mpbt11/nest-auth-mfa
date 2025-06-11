import { registerDecorator, ValidationOptions, ValidationArguments } from 'class-validator';

export function IsStrongPassword(validationOptions?: ValidationOptions) {
    return function (object: Object, propertyName: string) {
        registerDecorator({
            name: 'isStrongPassword',
            target: object.constructor,
            propertyName: propertyName,
            options: validationOptions,
            validator: {
                validate(value: any, args: ValidationArguments) {
                    if (typeof value !== 'string') return false;
                    
                    const minLength = 8;
                    const hasUpperCase = /[A-Z]/.test(value);
                    const hasLowerCase = /[a-z]/.test(value);
                    const hasNumbers = /\d/.test(value);
                    const hasSpecialChars = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]+/.test(value);

                    return value.length >= minLength &&
                           hasUpperCase &&
                           hasLowerCase &&
                           hasNumbers &&
                           hasSpecialChars;
                },
                defaultMessage(args: ValidationArguments) {
                    return 'A senha deve conter pelo menos 8 caracteres, incluindo: 1 número, 1 caractere especial, 1 letra maiúscula e 1 letra minúscula';
                }
            }
        });
    };
} 