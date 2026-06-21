import { Controller, Post, Get, Param, Body, HttpCode, HttpStatus, UseInterceptors, UseGuards } from '@nestjs/common';
import { AuthService } from '../services/auth.service';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { GroupsGuard } from '../guards/groups.guard';
import { Groups } from '../decorators/groups.decorator';
import {
    // RegisterDto,
    LoginDto,
    // ConfirmDto,
    ForgotPasswordDto,
    ResetPasswordDto,
    RefreshTokenDto,
    // ResendConfirmationDto,
    CreateGroupDto,
    GroupMembershipDto,
    AdminCreateUserDto
} from '../dto';
import { ResponseInterceptor } from '../interceptors/response.interceptor';

@Controller('auth')
@UseInterceptors(ResponseInterceptor)
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    // Endpoint legado desativado (cadastro é por convite no /admin)
    /*
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
    */

    @Post('login')
    @HttpCode(HttpStatus.OK)
    async login(@Body() body: LoginDto) {
        return this.authService.login(body.email, body.password);
    }

    // Endpoint legado desativado (confirmação de cadastro)
    /*
    @Post('confirm')
    @HttpCode(HttpStatus.OK)
    async confirm(@Body() body: ConfirmDto) {
        return this.authService.confirm(body.email, body.code);
    }
    */

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

    // Endpoint legado desativado (reenvio de código de confirmação)
    /*
    @Post('resend-confirmation')
    @HttpCode(HttpStatus.OK)
    async resendConfirmationCode(@Body() body: ResendConfirmationDto) {
        return this.authService.resendConfirmationCode(body.email);
    }
    */

    @Post('admin/create-user')
    @HttpCode(HttpStatus.OK)
    @UseGuards(JwtAuthGuard, GroupsGuard)
    @Groups('admin')
    async adminCreateUser(@Body() body: AdminCreateUserDto) {
        return this.authService.adminCreateUser(
            body.email,
            body.name,
            body.group
        );
    }

    @Post('admin/groups')
    @HttpCode(HttpStatus.OK)
    @UseGuards(JwtAuthGuard, GroupsGuard)
    @Groups('admin')
    async createGroup(@Body() body: CreateGroupDto) {
        return this.authService.createGroup(body.name, body.description);
    }

    @Post('admin/groups/add-user')
    @HttpCode(HttpStatus.OK)
    @UseGuards(JwtAuthGuard, GroupsGuard)
    @Groups('admin')
    async addUserToGroup(@Body() body: GroupMembershipDto) {
        return this.authService.addUserToGroup(body.email, body.group);
    }

    @Post('admin/groups/remove-user')
    @HttpCode(HttpStatus.OK)
    @UseGuards(JwtAuthGuard, GroupsGuard)
    @Groups('admin')
    async removeUserFromGroup(@Body() body: GroupMembershipDto) {
        return this.authService.removeUserFromGroup(body.email, body.group);
    }

    @Get('admin/groups/:group/users')
    @HttpCode(HttpStatus.OK)
    @UseGuards(JwtAuthGuard, GroupsGuard)
    @Groups('admin')
    async listUsersInGroup(@Param('group') group: string) {
        return this.authService.listUsersInGroup(group);
    }
}
