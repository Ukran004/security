const express = require('express');
const router = express.Router();
const ActivityLog = require('../models/ActivityLog');

// GET /api/activity-logs - Admin: view all logs
router.get('/', async (req, res) => {
    try {
        // Optionally add authentication/authorization here
        const logs = await ActivityLog.find().sort({ timestamp: -1 }).limit(100);
        res.json(logs);
    } catch (err) {
        res.status(500).json({ message: 'Failed to fetch activity logs', error: err.message });
    }
});

module.exports = router;
