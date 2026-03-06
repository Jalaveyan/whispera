import { Controller, Get, Post, Put, Delete, Body, Param, Headers, Res, HttpStatus } from '@nestjs/common';
import type { Response } from 'express';
import { UsersService } from './users.service';

class CreateUserDto {
    email: string;
    password?: string;
    traffic_limit?: number;
    valid_until?: string;
    obfs_profile?: string;
    marionette_profile?: string;
    russian_service?: string;
}

@Controller()
export class UsersController {
    constructor(private readonly usersService: UsersService) { }

    @Get('api/users')
    async getUsers(@Headers('authorization') auth: string, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const users = await this.usersService.getUsers(token);
            return res.json({ success: true, users });
        } catch {
            return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({ success: false, error: 'Failed to fetch users' });
        }
    }

    @Post('api/users')
    async createUser(
        @Headers('authorization') auth: string,
        @Body() dto: CreateUserDto,
        @Res() res: Response,
    ) {
        try {
            const token = auth?.replace('Bearer ', '');
            const user = await this.usersService.createUser(token, {
                username: dto.email,
                trafficLimit: dto.traffic_limit,
                expiryDate: dto.valid_until,
                obfsProfile: dto.obfs_profile,
                marionetteProfile: dto.marionette_profile,
                russianService: dto.russian_service,
            });
            return res.json({ success: true, user });
        } catch {
            return res.status(HttpStatus.BAD_REQUEST).json({ success: false, error: 'Failed to create user' });
        }
    }

    @Put('api/users/:id')
    async updateUser(
        @Headers('authorization') auth: string,
        @Param('id') id: string,
        @Body() body: { email?: string; status?: string },
        @Res() res: Response,
    ) {
        try {
            const token = auth?.replace('Bearer ', '');
            const user = await this.usersService.updateUser(token, id, {
                username: body.email,
                status: body.status,
            });
            return res.json({ success: true, user });
        } catch {
            return res.status(HttpStatus.BAD_REQUEST).json({ success: false, error: 'Failed to update user' });
        }
    }

    @Delete('api/users/:id')
    async deleteUser(
        @Headers('authorization') auth: string,
        @Param('id') id: string,
        @Res() res: Response,
    ) {
        try {
            const token = auth?.replace('Bearer ', '');
            await this.usersService.deleteUser(token, id);
            return res.json({ success: true });
        } catch {
            return res.status(HttpStatus.BAD_REQUEST).json({ success: false, error: 'Failed to delete user' });
        }
    }

    @Get('api/users/:id/stats')
    async getUserStats(
        @Headers('authorization') auth: string,
        @Param('id') id: string,
        @Res() res: Response,
    ) {
        try {
            const token = auth?.replace('Bearer ', '');
            const stats = await this.usersService.getUserStats(token, id);
            return res.json(stats);
        } catch {
            return res.status(HttpStatus.BAD_REQUEST).json({ success: false, error: 'Failed to fetch stats' });
        }
    }
}
