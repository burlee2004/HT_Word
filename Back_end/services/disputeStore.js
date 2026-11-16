const fs = require('fs');
const path = require('path');

const disputesFilePath = path.join(__dirname, '..', 'disputes.json');
const cacheDisputesFilePath = path.join(__dirname, '..', 'node_modules', '.cache', 'kgs work_data', 'disputes.json');
const dataDisputesFilePath = path.join(__dirname, '..', 'data', 'disputes.json');

function ensureDir(p) {
    try {
        const d = path.dirname(p);
        if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
    } catch(e) {}
}

function getDisputes() {
    for (const p of [disputesFilePath, dataDisputesFilePath, cacheDisputesFilePath]) {
        if (fs.existsSync(p)) {
            try {
                const content = fs.readFileSync(p, 'utf8');
                const parsed = JSON.parse(content);
                if (parsed && typeof parsed === 'object') return parsed;
            } catch (e) {}
        }
    }
    return {};
}

function saveDisputes(data) {
    const jsonStr = JSON.stringify(data || {}, null, 2);
    for (const p of [disputesFilePath, dataDisputesFilePath, cacheDisputesFilePath]) {
        try {
            ensureDir(p);
            fs.writeFileSync(p, jsonStr, 'utf8');
        } catch(e) {}
    }
}

module.exports = {
    getDisputes,
    saveDisputes
};
