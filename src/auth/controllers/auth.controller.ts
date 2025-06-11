import { Controller, Post, Body, HttpCode, HttpStatus, UseInterceptors } from '@nestjs/common';
import { AuthService } from '../services/auth.service';
import { 
    RegisterDto, 
    LoginDto, 
    ChallengeResponseDto, 
    ConfirmDto, 
    ForgotPasswordDto, 
    ResetPasswordDto, 
    RefreshTokenDto, 
    ResendConfirmationDto 
} from '../dto';
import { ResponseInterceptor } from '../interceptors/response.interceptor';

@Controller('auth')
@UseInterceptors(ResponseInterceptor)
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @Post('register')
    @HttpCode(HttpStatus.OK)
    async register(@Body() body: RegisterDto) {
        return this.authService.register(
            body.email,
            body.password,
            body.name,
            body.nickname,
            body.address,
            body.birthdate,
            body.gender,
            body.phone_number
        );
    }

    @Post('login')
    @HttpCode(HttpStatus.OK)
    async login(@Body() body: LoginDto) {
        return this.authService.login(body.email, body.password);
    }

    @Post('challenge')
    @HttpCode(HttpStatus.OK)
    async respondToChallenge(@Body() body: ChallengeResponseDto) {
        return this.authService.respondToChallenge(
            body.email, 
            body.session, 
            { code: body.code }
        );
    }

    @Post('confirm')
    @HttpCode(HttpStatus.OK)
    async confirm(@Body() body: ConfirmDto) {
        return this.authService.confirm(body.email, body.code);
    }

    @Post('forgot-password')
    @HttpCode(HttpStatus.OK)
    async forgotPassword(@Body() body: ForgotPasswordDto) {
        return this.authService.forgotPassword(body.email);
    }

    @Post('reset-password')
    @HttpCode(HttpStatus.OK)
    async resetPassword(@Body() body: ResetPasswordDto) {
        return this.authService.resetPassword(body.email, body.code, body.newPassword);
    }

    @Post('refresh')
    @HttpCode(HttpStatus.OK)
    async refresh(@Body() body: RefreshTokenDto) {
        return this.authService.refresh(body.refreshToken);
    }

    @Post('resend-confirmation')
    @HttpCode(HttpStatus.OK)
    async resendConfirmationCode(@Body() body: ResendConfirmationDto) {
        return this.authService.resendConfirmationCode(body.email);
    }

    @Post('admin/create-user')
    @HttpCode(HttpStatus.OK)
    async adminCreateUser(@Body() body: RegisterDto) {
        return this.authService.adminCreateUser(
            body.email,
            body.password,
            body.name,
            body.nickname,
            body.address,
            body.birthdate,
            body.gender,
            body.phone_number
        );
    }
} 