import { Controller, Get, Post, Delete, Body, Param, Headers, Res, HttpStatus } from '@nestjs/common';
import type { Response } from 'express';
import { RoutingService, RoutingRule } from './routing.service';

@Controller()
export class RoutingController {
    constructor(private readonly routingService: RoutingService) { }

    @Get('api/routing/rules')
    async getRules(@Headers('authorization') auth: string, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const rules = await this.routingService.getRules(token);
            return res.json({ success: true, rules });
        } catch {
            return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({ success: false, error: 'Failed to fetch routing rules' });
        }
    }

    @Post('api/routing/rules')
    async addRule(
        @Headers('authorization') auth: string,
        @Body() rule: Partial<RoutingRule>,
        @Res() res: Response,
    ) {
        try {
            const token = auth?.replace('Bearer ', '');
            const result = await this.routingService.addRule(token, rule);
            return res.json({ success: true, rule: result });
        } catch {
            return res.status(HttpStatus.BAD_REQUEST).json({ success: false, error: 'Failed to add routing rule' });
        }
    }

    @Delete('api/routing/rules/:id')
    async deleteRule(
        @Headers('authorization') auth: string,
        @Param('id') id: string,
        @Res() res: Response,
    ) {
        try {
            const token = auth?.replace('Bearer ', '');
            await this.routingService.deleteRule(token, id);
            return res.json({ success: true });
        } catch {
            return res.status(HttpStatus.BAD_REQUEST).json({ success: false, error: 'Failed to delete routing rule' });
        }
    }
}
