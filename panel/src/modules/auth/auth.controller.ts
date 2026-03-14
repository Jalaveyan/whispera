import { Controller, Post, Body, Get, Res, HttpStatus } from '@nestjs/common';
import type { Response } from 'express';
import { AuthService } from './auth.service';

class LoginDto {
    username: string;
    password: string;
}

class RegisterDto {
    email: string;
    password: string;
}

@Controller()
export class AuthController {
    constructor(private readonly authService: AuthService) { }

    @Get('login')
    loginPage(@Res() res: Response) {
        return res.redirect('/');
    }

    @Post('api/auth/login')
    async login(@Body() dto: LoginDto, @Res() res: Response) {
        try {
            const result = await this.authService.login(dto.username, dto.password);
            const maxAge = (result.expires_in || 1800) * 1000;
            res.cookie('token', result.token, {
                httpOnly: true,
                sameSite: 'strict',
                maxAge,
                secure: false,
            });
            return res.json({
                success: true,
                token: result.token,
                expires_in: result.expires_in || 1800,
                user: result.user,
            });
        } catch (err) {
            if (err?.response?.status === 429) {
                return res.status(429).json({ success: false, error: 'Too many login attempts. Please wait 1 minute.' });
            }
            return res.status(HttpStatus.UNAUTHORIZED).json({ success: false, error: 'Invalid credentials' });
        }
    }

    @Post('api/auth/register')
    async register(@Body() dto: RegisterDto, @Res() res: Response) {
        try {
            const result = await this.authService.registerUser(dto.email, dto.password);
            return res.json(result);
        } catch {
            return res.status(HttpStatus.BAD_REQUEST).json({ success: false, error: 'Registration failed' });
        }
    }

    @Post('api/auth/logout')
    logout(@Res() res: Response) {
        res.clearCookie('token');
        return res.json({ success: true });
    }
}
