import { Controller, Get, Post, Body, Headers, Query, Res, HttpStatus } from '@nestjs/common';
import type { Response } from 'express';
import { SystemService } from './system.service';

@Controller()
export class SystemController {
    constructor(private readonly systemService: SystemService) { }

    @Get('api/system/info')
    async getSystemInfo(@Headers('authorization') auth: string, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const info = await this.systemService.getSystemInfo(token);
            return res.json(info);
        } catch (err: any) {
            const status = err?.response?.status || HttpStatus.INTERNAL_SERVER_ERROR;
            return res.status(status).json({ success: false, error: err?.response?.data?.error || err?.message || 'Failed to fetch system info' });
        }
    }

    @Get('api/stats')
    async getStats(@Headers('authorization') auth: string, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const stats = await this.systemService.getStats(token);
            return res.json(stats);
        } catch (err: any) {
            const status = err?.response?.status || HttpStatus.INTERNAL_SERVER_ERROR;
            return res.status(status).json({ success: false, error: err?.response?.data?.error || err?.message || 'Failed to fetch stats' });
        }
    }

    @Post('api/system/reload')
    async reloadConfig(@Headers('authorization') auth: string, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            await this.systemService.reloadConfig(token);
            return res.json({ success: true, message: 'Config reloaded' });
        } catch (err: any) {
            const status = err?.response?.status || HttpStatus.INTERNAL_SERVER_ERROR;
            return res.status(status).json({ success: false, error: err?.response?.data?.error || err?.message || 'Failed to reload config' });
        }
    }

    @Get('api/health')
    async getHealth(@Res() res: Response) {
        try {
            const health = await this.systemService.getHealth();
            return res.json(health);
        } catch {
            return res.status(HttpStatus.SERVICE_UNAVAILABLE).json({ status: 'unavailable' });
        }
    }

    @Get('api/v1/config')
    async getConfig(@Headers('authorization') auth: string, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.systemService.getConfig(token);
            return res.json(data);
        } catch (err: any) {
            return res.status(err?.response?.status || HttpStatus.INTERNAL_SERVER_ERROR)
                .json({ error: err?.response?.data?.error || err?.message || 'Failed' });
        }
    }

    @Post('api/v1/config/update')
    async updateConfig(@Headers('authorization') auth: string, @Body() body: any, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.systemService.updateConfig(token, body);
            return res.json(data);
        } catch (err: any) {
            return res.status(err?.response?.status || HttpStatus.INTERNAL_SERVER_ERROR)
                .json({ error: err?.response?.data?.error || err?.message || 'Failed' });
        }
    }

    @Get('api/backup')
    async getBackup(@Headers('authorization') auth: string, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.systemService.getBackup(token);
            return res.json(data);
        } catch (err: any) {
            return res.status(err?.response?.status || HttpStatus.INTERNAL_SERVER_ERROR)
                .json({ error: err?.response?.data?.error || err?.message || 'Failed' });
        }
    }

    @Post('api/backup/restore')
    async restoreBackup(@Headers('authorization') auth: string, @Body() body: any, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.systemService.restoreBackup(token, body);
            return res.json(data);
        } catch (err: any) {
            return res.status(err?.response?.status || HttpStatus.INTERNAL_SERVER_ERROR)
                .json({ error: err?.response?.data?.error || err?.message || 'Failed' });
        }
    }

    @Post('api/v1/config/renew-cert')
    async renewCert(@Headers('authorization') auth: string, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.systemService.renewCert(token);
            return res.json(data);
        } catch (err: any) {
            return res.status(err?.response?.status || HttpStatus.INTERNAL_SERVER_ERROR)
                .json({ error: err?.response?.data?.error || err?.message || 'Failed' });
        }
    }

    @Get('api/probe/stats')
    async getProbeStats(@Headers('authorization') auth: string, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.systemService.getProbeStats(token);
            return res.json(data);
        } catch (err: any) {
            return res.status(err?.response?.status || HttpStatus.SERVICE_UNAVAILABLE)
                .json({ error: err?.response?.data?.error || err?.message });
        }
    }

    @Post('api/probe/block')
    async probeBlock(@Headers('authorization') auth: string, @Body('ip') ip: string, @Body('reason') reason: string, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.systemService.probeBlockIP(token, ip, reason || 'manual');
            return res.json(data);
        } catch (err: any) {
            return res.status(err?.response?.status || HttpStatus.INTERNAL_SERVER_ERROR)
                .json({ error: err?.response?.data?.error || err?.message });
        }
    }

    @Post('api/probe/unblock')
    async probeUnblock(@Headers('authorization') auth: string, @Body('ip') ip: string, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.systemService.probeUnblockIP(token, ip);
            return res.json(data);
        } catch (err: any) {
            return res.status(err?.response?.status || HttpStatus.INTERNAL_SERVER_ERROR)
                .json({ error: err?.response?.data?.error || err?.message });
        }
    }

    @Get('api/ml/config')
    async getMLConfig(@Headers('authorization') auth: string, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.systemService.getMLConfig(token);
            return res.json(data);
        } catch (err: any) {
            return res.status(err?.response?.status || HttpStatus.INTERNAL_SERVER_ERROR)
                .json({ error: err?.response?.data?.error || err?.message || 'Failed' });
        }
    }

    @Post('api/ml/token/rotate')
    async rotateMLToken(@Headers('authorization') auth: string, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.systemService.rotateMLToken(token);
            return res.json(data);
        } catch (err: any) {
            return res.status(err?.response?.status || HttpStatus.INTERNAL_SERVER_ERROR)
                .json({ error: err?.response?.data?.error || err?.message || 'Failed' });
        }
    }

    @Get('api/qr')
    async generateQR(@Query('data') data: string, @Res() res: Response) {
        if (!data) {
            return res.status(HttpStatus.BAD_REQUEST).json({ error: 'data param required' });
        }
        try {
            // eslint-disable-next-line @typescript-eslint/no-require-imports
            const QRCode = require('qrcode');
            const url: string = await QRCode.toDataURL(data, {
                width: 220,
                margin: 2,
                errorCorrectionLevel: 'L',
                color: { dark: '#000000', light: '#ffffff' },
            });
            return res.json({ url });
        } catch (err: any) {
            return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({ error: err?.message || 'QR generation failed' });
        }
    }
}
