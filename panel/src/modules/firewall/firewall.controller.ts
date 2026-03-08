import { Controller, Get, Post, Delete, Body, Headers, Res, HttpStatus } from '@nestjs/common';
import type { Response } from 'express';
import { FirewallService } from './firewall.service';

@Controller()
export class FirewallController {
    constructor(private readonly firewallService: FirewallService) { }

    @Get('api/firewall/status')
    async getStatus(@Headers('authorization') auth: string, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.firewallService.getStatus(token);
            return res.json(data);
        } catch (err: any) {
            const msg = err?.response?.data?.error || err?.message || 'Failed to get firewall status';
            return res.status(err?.response?.status || HttpStatus.INTERNAL_SERVER_ERROR).json({ success: false, error: msg });
        }
    }

    @Post('api/firewall/rules')
    async addRule(@Headers('authorization') auth: string, @Body() body: any, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.firewallService.addRule(token, body);
            return res.json(data);
        } catch (err: any) {
            const msg = err?.response?.data?.error || err?.message || 'Failed to add rule';
            return res.status(err?.response?.status || HttpStatus.BAD_REQUEST).json({ success: false, error: msg });
        }
    }

    @Delete('api/firewall/rules')
    async deleteRule(@Headers('authorization') auth: string, @Body() body: any, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.firewallService.deleteRule(token, body.number);
            return res.json(data);
        } catch (err: any) {
            const msg = err?.response?.data?.error || err?.message || 'Failed to delete rule';
            return res.status(err?.response?.status || HttpStatus.BAD_REQUEST).json({ success: false, error: msg });
        }
    }

    @Post('api/firewall/toggle')
    async toggle(@Headers('authorization') auth: string, @Body() body: any, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.firewallService.toggle(token, body.enable);
            return res.json(data);
        } catch (err: any) {
            const msg = err?.response?.data?.error || err?.message || 'Failed to toggle firewall';
            return res.status(err?.response?.status || HttpStatus.INTERNAL_SERVER_ERROR).json({ success: false, error: msg });
        }
    }
}
