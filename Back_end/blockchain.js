const { ethers } = require('ethers');

// Khởi tạo Provider kết nối với RPC Node (VD: Sepolia)
const RPC_URL = process.env.BLOCKCHAIN_RPC_URL || 'https://rpc.sepolia.org';
const provider = new ethers.JsonRpcProvider(RPC_URL);

// Khởi tạo Wallet (Ví Admin) từ Private Key
const PRIVATE_KEY = process.env.BLOCKCHAIN_PRIVATE_KEY;
let wallet;
if (PRIVATE_KEY) {
    wallet = new ethers.Wallet(PRIVATE_KEY, provider);
}

// Địa chỉ Smart Contract
const CONTRACT_ADDRESS = process.env.BLOCKCHAIN_CONTRACT_ADDRESS;

// ABI của HTWorkLedger Smart Contract
const ABI = [
    "function addBalance(string memory userId, uint256 amount) public",
    "function deductBalance(string memory userId, uint256 amount) public",
    "function transfer(string memory fromUserId, string memory toUserId, uint256 amount) public",
    "function getBalance(string memory userId) public view returns (uint256)",
    "event BalanceAdded(string userId, uint256 amount, uint256 newBalance)",
    "event BalanceDeducted(string userId, uint256 amount, uint256 newBalance)",
    "event EscrowTransferred(string fromUserId, string toUserId, uint256 amount)"
];

let ledgerContract;
if (wallet && CONTRACT_ADDRESS) {
    ledgerContract = new ethers.Contract(CONTRACT_ADDRESS, ABI, wallet);
}

const isConfigured = () => {
    return !!ledgerContract;
};

// --- Các hàm tiện ích ---

// Cập nhật số dư khi nạp tiền
async function addBalance(userId, amount) {
    if (!isConfigured()) return false;
    try {
        console.log(`[Blockchain] Thêm ${amount} cho user ${userId}...`);
        const tx = await ledgerContract.addBalance(userId, amount);
        const receipt = await tx.wait(); // Đợi giao dịch xác nhận
        console.log(`[Blockchain] Giao dịch thành công! TxHash: ${receipt.hash}`);
        return true;
    } catch (error) {
        console.error(`[Blockchain Lỗi] addBalance:`, error);
        return false;
    }
}

// Trừ số dư khi rút tiền hoặc nạp tiền bị lỗi/hoàn trả
async function deductBalance(userId, amount) {
    if (!isConfigured()) return false;
    try {
        console.log(`[Blockchain] Trừ ${amount} của user ${userId}...`);
        const tx = await ledgerContract.deductBalance(userId, amount);
        const receipt = await tx.wait();
        console.log(`[Blockchain] Giao dịch thành công! TxHash: ${receipt.hash}`);
        return true;
    } catch (error) {
        console.error(`[Blockchain Lỗi] deductBalance:`, error);
        throw new Error('Lỗi đồng bộ Blockchain (Trừ tiền)');
    }
}

// Chuyển tiền (Sử dụng cho Giải ngân Escrow)
async function transferBalance(fromUserId, toUserId, amount) {
    if (!isConfigured()) return false;
    try {
        console.log(`[Blockchain] Chuyển ${amount} từ ${fromUserId} sang ${toUserId}...`);
        const tx = await ledgerContract.transfer(fromUserId, toUserId, amount);
        const receipt = await tx.wait();
        console.log(`[Blockchain] Giao dịch thành công! TxHash: ${receipt.hash}`);
        return true;
    } catch (error) {
        console.error(`[Blockchain Lỗi] transferBalance:`, error);
        throw new Error('Lỗi đồng bộ Blockchain (Chuyển tiền)');
    }
}

// Lấy số dư (Để đối chiếu chống Hack)
async function getBalance(userId) {
    if (!isConfigured()) return null;
    try {
        const balance = await ledgerContract.getBalance(userId);
        return Number(balance);
    } catch (error) {
        console.error(`[Blockchain Lỗi] getBalance:`, error);
        return null;
    }
}

module.exports = {
    isConfigured,
    addBalance,
    deductBalance,
    transferBalance,
    getBalance
};
