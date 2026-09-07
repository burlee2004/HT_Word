const fs = require('fs');
const path = require('path');

const disputesFilePath = path.join(__dirname, '..', 'disputes.json');

function getDisputes() {
    if (fs.existsSync(disputesFilePath)) {
        try {
            return JSON.parse(fs.readFileSync(disputesFilePath, 'utf8'));
        } catch (e) {
            return {};
        }
    }
    return {};
}

function saveDisputes(data) {
    fs.writeFileSync(disputesFilePath, JSON.stringify(data, null, 2));
}

module.exports = {
    getDisputes,
    saveDisputes
};
