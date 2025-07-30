const ActivityLog = require('../models/ActivityLog');

async function logActivity({ userId, action, details, ip }) {
    try {
        await ActivityLog.create({ userId, action, details, ip });
    } catch (err) {
        // Optionally log error to a file or monitoring system
        console.error('Activity logging failed:', err);
    }
}

module.exports = logActivity;
