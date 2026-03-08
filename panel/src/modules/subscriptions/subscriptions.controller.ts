import { Controller, Get, Post, Body, Headers, Req, Res, HttpStatus } from '@nestjs/common';
import type { Request } from 'express';
import type { Response } from 'express';
import { SubscriptionsService } from './subscriptions.service';
import type { CreateSubscriptionDto } from './subscriptions.service';

@Controller()
export class SubscriptionsController {
    constructor(private readonly subscriptionsService: SubscriptionsService) { }

    @Get('api/subscriptions')
    async getSubscriptions(@Headers('authorization') auth: string, @Req() req: Request, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const host = req.headers['x-forwarded-host'] as string || req.headers['host'] as string || '';
            const proto = req.headers['x-forwarded-proto'] as string || (req.secure ? 'https' : 'http');
            const subscriptions = await this.subscriptionsService.getSubscriptions(token, host, proto);
            return res.json({ success: true, subscriptions });
        } catch (err: any) {
            const msg = err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to fetch subscriptions';
            return res.status(err?.response?.status || HttpStatus.INTERNAL_SERVER_ERROR).json({ success: false, error: msg });
        }
    }

    @Post('api/subscriptions/add')
    async addSubscription(
        @Headers('authorization') auth: string,
        @Body() dto: CreateSubscriptionDto,
        @Req() req: Request,
        @Res() res: Response,
    ) {
        try {
            const token = auth?.replace('Bearer ', '');
            const host = req.headers['x-forwarded-host'] as string || req.headers['host'] as string || '';
            const proto = req.headers['x-forwarded-proto'] as string || (req.secure ? 'https' : 'http');
            const result = await this.subscriptionsService.addSubscription(token, dto, host, proto);
            return res.json({ success: true, subscription: result });
        } catch (err: any) {
            const msg = err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to add subscription';
            return res.status(err?.response?.status || HttpStatus.BAD_REQUEST).json({ success: false, error: msg });
        }
    }

    @Post('api/subscriptions/update')
    async updateSubscription(
        @Headers('authorization') auth: string,
        @Body() body: { id: string } & Partial<CreateSubscriptionDto>,
        @Res() res: Response,
    ) {
        try {
            const token = auth?.replace('Bearer ', '');
            const { id, ...dto } = body;
            const result = await this.subscriptionsService.updateSubscription(token, id, dto);
            return res.json({ success: true, subscription: result });
        } catch (err: any) {
            const msg = err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to update subscription';
            return res.status(err?.response?.status || HttpStatus.BAD_REQUEST).json({ success: false, error: msg });
        }
    }

    @Post('api/subscriptions/delete')
    async deleteSubscription(
        @Headers('authorization') auth: string,
        @Body('id') id: string,
        @Res() res: Response,
    ) {
        try {
            const token = auth?.replace('Bearer ', '');
            await this.subscriptionsService.deleteSubscription(token, id);
            return res.json({ success: true });
        } catch (err: any) {
            const msg = err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to delete subscription';
            return res.status(err?.response?.status || HttpStatus.BAD_REQUEST).json({ success: false, error: msg });
        }
    }

    @Post('api/subscriptions/update-all')
    async updateAll(@Headers('authorization') auth: string, @Res() res: Response) {
        void auth;
        return res.json({ success: true });
    }
}
