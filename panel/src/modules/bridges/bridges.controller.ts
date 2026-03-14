import { Controller, Get, Post, Body, Headers, Res, HttpStatus } from '@nestjs/common';
import type { Response } from 'express';
import { BridgesService, Bridge } from './bridges.service';

@Controller()
export class BridgesController {
    constructor(private readonly bridgesService: BridgesService) { }

    @Get('api/bridges')
    async getBridges(@Headers('authorization') auth: string, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const bridges = await this.bridgesService.getBridges(token);
            return res.json({ success: true, bridges });
        } catch (err: any) {
            const status = err?.response?.status || HttpStatus.INTERNAL_SERVER_ERROR;
            return res.status(status).json({ success: false, error: err?.response?.data?.error || err?.message || 'Failed to fetch bridges' });
        }
    }

    @Post('api/bridges')
    async addBridge(
        @Headers('authorization') auth: string,
        @Body() bridge: Partial<Bridge>,
        @Res() res: Response,
    ) {
        try {
            const token = auth?.replace('Bearer ', '');
            const result = await this.bridgesService.addBridge(token, bridge);
            return res.json({ success: true, bridge: result });
        } catch (err: any) {
            const status = err?.response?.status || HttpStatus.BAD_REQUEST;
            return res.status(status).json({ success: false, error: err?.response?.data?.error || err?.message || 'Failed to add bridge' });
        }
    }

    @Post('api/bridges/delete')
    async deleteBridge(
        @Headers('authorization') auth: string,
        @Body('id') id: string,
        @Res() res: Response,
    ) {
        try {
            const token = auth?.replace('Bearer ', '');
            await this.bridgesService.deleteBridge(token, id);
            return res.json({ success: true });
        } catch (err: any) {
            const status = err?.response?.status || HttpStatus.BAD_REQUEST;
            return res.status(status).json({ success: false, error: err?.response?.data?.error || err?.message || 'Failed to delete bridge' });
        }
    }

    @Get('api/bridges/cloudinit')
    async getCloudInit(@Headers('authorization') auth: string, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const script = await this.bridgesService.getCloudInit(token);
            return res.send(script);
        } catch (err: any) {
            const status = err?.response?.status || HttpStatus.INTERNAL_SERVER_ERROR;
            return res.status(status).send('Failed to generate cloud-init');
        }
    }

    @Get('api/bridge-admin')
    async getBridgesAdmin(@Headers('authorization') auth: string, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.bridgesService.getBridgesAdmin(token);
            return res.json(data);
        } catch (err: any) {
            const status = err?.response?.status || HttpStatus.INTERNAL_SERVER_ERROR;
            return res.status(status).json({ error: err?.response?.data?.error || err?.message });
        }
    }

    @Get('api/bridge-stats')
    async getBridgeStats(@Headers('authorization') auth: string, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.bridgesService.getBridgeStats(token);
            return res.json(data);
        } catch (err: any) {
            const status = err?.response?.status || HttpStatus.INTERNAL_SERVER_ERROR;
            return res.status(status).json({ error: err?.response?.data?.error || err?.message });
        }
    }

    @Post('api/bridge-check')
    async checkBridge(@Headers('authorization') auth: string, @Body('id') id: string, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.bridgesService.checkBridge(token, id);
            return res.json(data);
        } catch (err: any) {
            const status = err?.response?.status || HttpStatus.INTERNAL_SERVER_ERROR;
            return res.status(status).json({ error: err?.response?.data?.error || err?.message });
        }
    }

    @Get('api/bridge-token')
    async getBridgeToken(@Headers('authorization') auth: string, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.bridgesService.getToken(token);
            return res.json(data);
        } catch (err: any) {
            const status = err?.response?.status || HttpStatus.INTERNAL_SERVER_ERROR;
            return res.status(status).json({ error: err?.response?.data?.error || err?.message });
        }
    }

    @Post('api/bridge-token-regenerate')
    async regenerateBridgeToken(@Headers('authorization') auth: string, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.bridgesService.regenerateToken(token);
            return res.json(data);
        } catch (err: any) {
            const status = err?.response?.status || HttpStatus.INTERNAL_SERVER_ERROR;
            return res.status(status).json({ error: err?.response?.data?.error || err?.message });
        }
    }

    @Post('api/bridge-add')
    async addBridgeDirect(@Headers('authorization') auth: string, @Body() body: any, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.bridgesService.addBridgeDirect(token, body);
            return res.json(data);
        } catch (err: any) {
            const status = err?.response?.status || HttpStatus.BAD_REQUEST;
            return res.status(status).json({ error: err?.response?.data?.error || err?.message });
        }
    }

    @Post('api/bridge-delete')
    async deleteBridgeDirect(@Headers('authorization') auth: string, @Body() body: any, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.bridgesService.deleteBridgeDirect(token, body);
            return res.json(data);
        } catch (err: any) {
            const status = err?.response?.status || HttpStatus.BAD_REQUEST;
            return res.status(status).json({ error: err?.response?.data?.error || err?.message });
        }
    }

    @Get('api/bridge-map')
    async getBridgeMap(@Headers('authorization') auth: string, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.bridgesService.getBridgeMap(token);
            return res.json(data);
        } catch (err: any) {
            const status = err?.response?.status || HttpStatus.INTERNAL_SERVER_ERROR;
            return res.status(status).json({ error: err?.response?.data?.error || err?.message });
        }
    }

    @Post('api/bridge-connect')
    async connectToBridge(@Headers('authorization') auth: string, @Body('bridge_id') bridgeId: string, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.bridgesService.connectToBridge(token, bridgeId);
            return res.json(data);
        } catch (err: any) {
            const status = err?.response?.status || HttpStatus.BAD_REQUEST;
            return res.status(status).json({ error: err?.response?.data?.error || err?.message });
        }
    }

    @Post('api/bridge-scan')
    async scanBridges(@Headers('authorization') auth: string, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.bridgesService.scanBridges(token);
            return res.json(data);
        } catch (err: any) {
            const status = err?.response?.status || HttpStatus.INTERNAL_SERVER_ERROR;
            return res.status(status).json({ error: err?.response?.data?.error || err?.message });
        }
    }

    @Get('api/bridge-cloudinit')
    async getBridgeCloudinit(@Headers('authorization') auth: string, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const script = await this.bridgesService.getCloudInit(token);
            return res.send(script);
        } catch (err: any) {
            const status = err?.response?.status || HttpStatus.INTERNAL_SERVER_ERROR;
            return res.status(status).send('Failed to generate cloud-init');
        }
    }
}
