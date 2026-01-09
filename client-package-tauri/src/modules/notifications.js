
// Notification Center Module

export function initNotifications() {
    const btn = document.getElementById('btn-notify');
    const popup = document.getElementById('notifications-popup');
    const clearBtn = document.getElementById('clear-notifications');

    if (!btn || !popup) return;

    // Toggle Popup
    btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const isVisible = popup.classList.contains('show');

        // Close all other popups if any
        document.querySelectorAll('.popup.show').forEach(p => p.classList.remove('show'));

        if (isVisible) {
            popup.classList.remove('show');
        } else {
            popup.classList.add('show');
        }
    });

    // Close when clicking outside
    document.addEventListener('click', (e) => {
        if (!popup.contains(e.target) && !btn.contains(e.target)) {
            popup.classList.remove('show');
        }
    });

    // Clear Action
    if (clearBtn) {
        clearBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            // TODO: Clear actual notifications array
            popup.classList.remove('show');
        });
    }
}
