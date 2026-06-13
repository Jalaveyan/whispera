import { api } from '../services/api.js';

export const sessionsPage = {
    async loadSessions() {
        const tbody = document.getElementById('sessions-table-body');
        try {
            const data = await api.getSessions();
            const sessions = data.sessions || [];

            if (sessions.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="text-center">Нет активных сессий</td></tr>';
                return;
            }

            tbody.innerHTML = sessions.map(s => `
    <tr>
          <td>${s.user_id || '-'}</td>
          <td>${s.client_ip || '-'}</td>
          <td>${this.formatTime(s.connected_at)}</td>
          <td>${this.formatBytes(s.bytes_in || 0)} / ${this.formatBytes(s.bytes_out || 0)}</td>
          <td>
            <button class="btn btn-danger btn-sm" data-act="killSession" data-arg="${escapeHtml(String(s.id))}">Завершить</button>
          </td>
        </tr>
    `).join('');
        } catch (error) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center">Ошибка загрузки</td></tr>';
        }
    },
    async killSession(id) {
        if (!(await this.showConfirm('Завершить сессию?'))) return;
        try {
            await api.killSession(id);
            this.loadSessions();
            this.showNotification('Сессия завершена', 'success');
        } catch (error) {
            this.showNotification('Ошибка: ' + error.message, 'error');
        }
    }
};
