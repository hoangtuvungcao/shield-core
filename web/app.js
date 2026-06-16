// Biến toàn cục
let apiKey = localStorage.getItem('shield_api_key') || '';
let refreshTimer = null;
let refreshInterval = null;

// Khởi tạo
document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initSidebar();
    
    // Nếu chưa có API Key, yêu cầu nhập
    if (!apiKey) {
        promptApiKey();
    } else {
        startAutoRefresh();
    }

    // Gắn sự kiện cho các nút chức năng
    document.getElementById('btnRefresh').addEventListener('click', loadCurrentTab);
    document.getElementById('btnSettings').addEventListener('click', promptApiKey);
    
    document.getElementById('btnAddBlacklist').addEventListener('click', addBlacklistIP);
    document.getElementById('btnAddWhitelist').addEventListener('click', addWhitelistIP);
    document.getElementById('btnAddRoute').addEventListener('click', addRoute);
    document.getElementById('btnAddASN').addEventListener('click', addASN);
    document.getElementById('btnAddCountry').addEventListener('click', addCountry);
});

// --- Hệ thống Điều hướng (Tabs) ---
function initNavigation() {
    const navItems = document.querySelectorAll('.nav-item[data-tab]');
    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const tabId = item.getAttribute('data-tab');
            
            // Đổi active nav
            navItems.forEach(n => n.classList.remove('active'));
            item.classList.add('active');
            
            // Đổi active tab content
            document.querySelectorAll('.tab-pane').forEach(t => t.classList.remove('active'));
            const targetTab = document.getElementById(`tab-${tabId}`);
            if (targetTab) {
                targetTab.classList.add('active');
                
                // Cập nhật tiêu đề
                document.getElementById('pageTitle').innerText = item.innerText.trim();
                
                // Tải dữ liệu cho tab mới
                loadTab(tabId);
            }
            
            // Đóng sidebar trên mobile
            if (window.innerWidth <= 768) {
                document.getElementById('sidebar').classList.remove('open');
            }
        });
    });
}

function initSidebar() {
    const btnMenu = document.getElementById('btnMenu');
    const closeSidebar = document.getElementById('closeSidebar');
    const sidebar = document.getElementById('sidebar');

    btnMenu.addEventListener('click', () => sidebar.classList.add('open'));
    closeSidebar.addEventListener('click', () => sidebar.classList.remove('open'));
}

// --- Fetch API Wrapper ---
async function apiRequest(endpoint, method = 'GET') {
    if (!apiKey) throw new Error('Chưa cấu hình API Key');
    
    // Đối với các GET/DELETE endpoint của API hiện tại, tham số nằm ở query, không phải JSON body.
    const url = `/api/${endpoint}`;
    
    try {
        const response = await fetch(url, {
            method: method,
            headers: {
                'X-API-Key': apiKey,
                'Content-Type': 'application/json'
            }
        });
        
        if (!response.ok) {
            const errText = await response.text();
            throw new Error(errText || `HTTP Lỗi ${response.status}`);
        }
        
        // Nếu API trả về JSON thì parse, nếu là chuỗi (như lúc thêm/xoá thành công) thì trả text
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            return await response.json();
        }
        return await response.text();
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}

// Lấy trạng thái Health (Public route, nhưng ta dùng fetch)
async function fetchHealth() {
    try {
        const response = await fetch('/health');
        if (!response.ok) throw new Error('Health check failed');
        const data = await response.json();
        
        document.getElementById('valUptime').innerText = formatUptime(data.uptime_sec);
        document.getElementById('valXDP').innerText = data.xdp_loaded ? 'Đang chạy (NATIVE/DRIVER)' : 'Lỗi';
        document.getElementById('valXDP').className = data.xdp_loaded ? 'stat-value text-green' : 'stat-value text-red';
        
        document.getElementById('hStatus').innerText = data.status.toUpperCase();
        document.getElementById('hStatus').className = data.status === 'healthy' ? 'badge badge-success' : 'badge';
        
        document.getElementById('hASN').innerText = data.geoip.asn ? 'Đã tải' : 'Trống';
        document.getElementById('hCountry').innerText = data.geoip.country ? 'Đã tải' : 'Trống';
        
        if (data.system) {
            const mbTotal = (data.system.ram_total / 1024 / 1024).toFixed(0);
            const mbUsed = (data.system.ram_used / 1024 / 1024).toFixed(0);
            document.getElementById('valRam').innerText = `${mbUsed} / ${mbTotal} MB`;
            document.getElementById('valLoad').innerText = data.system.load_1m.toFixed(2);
            document.getElementById('valProcs').innerText = data.system.procs;
        }

        updateConnectionStatus(true);
    } catch (error) {
        updateConnectionStatus(false);
    }
}

// Lấy thông số Passed/Dropped
async function fetchStats() {
    try {
        const data = await apiRequest('stats');
        // Animation đếm số
        animateValue('valPassed', data.pass_count);
        animateValue('valDropped', data.drop_count);
    } catch (error) {
        // Lỗi silent
    }
}

// --- Trình tải dữ liệu các Tab ---
function loadCurrentTab() {
    const activeTab = document.querySelector('.nav-item.active');
    if (activeTab) {
        loadTab(activeTab.getAttribute('data-tab'));
    }
}

function loadTab(tabId) {
    if (tabId === 'dashboard') {
        fetchHealth();
        fetchStats();
    } else if (tabId === 'blacklist') {
        loadBlacklist();
    } else if (tabId === 'whitelist') {
        loadWhitelist();
    } else if (tabId === 'routing') {
        loadRouting();
    } else if (tabId === 'logs') {
        loadLogs();
    }
}

function stopAutoRefresh() {
    if (refreshInterval) {
        clearInterval(refreshInterval);
        refreshInterval = null;
    }
    if (refreshTimer) {
        clearInterval(refreshTimer);
        refreshTimer = null;
    }
}

function startAutoRefresh() {
    stopAutoRefresh();
    // Tải ngay lần đầu
    fetchHealth();
    fetchStats();
    // Sau đó tự động cập nhật mỗi 2 giây
    refreshInterval = setInterval(() => {
        const activeTab = document.querySelector('.nav-item.active');
        if (!activeTab) return;
        const tab = activeTab.getAttribute('data-tab');
        if (tab === 'dashboard') {
            fetchHealth();
            fetchStats();
        } else if (tab === 'logs') {
            loadLogs();
        }
    }, 2000);
}

// --- Cụ thể từng tính năng ---

async function loadBlacklist() {
    const tbody = document.getElementById('blacklistTable');
    tbody.innerHTML = '<tr><td colspan="3" class="text-center">Đang tải...</td></tr>';
    try {
        const ips = await apiRequest('blacklist');
        if (!ips || ips.length === 0) {
            tbody.innerHTML = '<tr><td colspan="3" class="text-center">Không có IP/Dải mạng nào bị chặn.</td></tr>';
            return;
        }
        tbody.innerHTML = '';
        
        // Render top 100 to prevent browser freeze if massive cidrs returned
        const toRender = ips.slice(0, 100);
        toRender.forEach((ip, idx) => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${idx + 1}</td>
                <td style="font-family: monospace;">${ip}</td>
                <td><button class="btn btn-sm btn-danger" onclick="removeBlacklist('${ip}')"><i class="fa-solid fa-trash"></i> Xoá</button></td>
            `;
            tbody.appendChild(tr);
        });
        if (ips.length > 100) {
            const tr = document.createElement('tr');
            tr.innerHTML = `<td colspan="3" class="text-center text-secondary">... và ${ips.length - 100} dải mạng khác</td>`;
            tbody.appendChild(tr);
        }
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="3" class="text-center text-red">Lỗi tải dữ liệu: ${e.message}</td></tr>`;
    }
}

async function loadWhitelist() {
    const tbody = document.getElementById('whitelistTable');
    tbody.innerHTML = '<tr><td colspan="3" class="text-center">Đang tải...</td></tr>';
    try {
        const ips = await apiRequest('whitelist');
        if (!ips || ips.length === 0) {
            tbody.innerHTML = '<tr><td colspan="3" class="text-center">Danh sách Ưu tiên đang trống.</td></tr>';
            return;
        }
        tbody.innerHTML = '';
        
        const toRender = ips.slice(0, 100);
        toRender.forEach((ip, idx) => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${idx + 1}</td>
                <td style="font-family: monospace; color: var(--accent-green);">${ip}</td>
                <td><button class="btn btn-sm btn-danger" onclick="removeWhitelistIP('${ip}')"><i class="fa-solid fa-trash"></i> Xoá</button></td>
            `;
            tbody.appendChild(tr);
        });
        if (ips.length > 100) {
            const tr = document.createElement('tr');
            tr.innerHTML = `<td colspan="3" class="text-center text-secondary">... và ${ips.length - 100} dải mạng khác</td>`;
            tbody.appendChild(tr);
        }
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="3" class="text-center text-red">Lỗi tải dữ liệu: ${e.message}</td></tr>`;
    }
}

async function loadLogs() {
    const tbody = document.getElementById('logsTable');
    try {
        const logs = await apiRequest('logs');
        if (!logs || logs.length === 0) {
            tbody.innerHTML = '<tr><td class="text-center" style="color: var(--text-secondary);">Chưa có sự kiện đánh chặn nào được ghi nhận.</td></tr>';
            return;
        }
        tbody.innerHTML = '';
        logs.forEach((log) => {
            const tr = document.createElement('tr');
            
            // Format time
            const date = new Date(log.timestamp);
            const timeStr = isNaN(date) ? log.timestamp : date.toLocaleTimeString('vi-VN');
            
            let color = 'var(--text-secondary)';
            if (log.event.includes('ADD') || log.event.includes('ISOLATE') || log.event.includes('BLOCK')) color = 'var(--accent-red)';
            if (log.event.includes('PASS') || log.event.includes('WHITELIST')) color = 'var(--accent-green)';
            if (log.event.includes('REMOVE') || log.event.includes('FREE')) color = 'var(--accent-blue)';

            tr.innerHTML = `
                <td style="width: 120px; color: var(--text-secondary); border-bottom: 1px solid rgba(255,255,255,0.05); padding: 8px;">[${timeStr}]</td>
                <td style="width: 150px; font-weight: bold; color: ${color}; border-bottom: 1px solid rgba(255,255,255,0.05); padding: 8px;">${log.event}</td>
                <td style="width: 150px; color: #fff; border-bottom: 1px solid rgba(255,255,255,0.05); padding: 8px;">${log.ip || '-'}</td>
                <td style="border-bottom: 1px solid rgba(255,255,255,0.05); padding: 8px; color: #bbb;">${log.reason || ''}</td>
                <td style="width: 100px; text-align: right; border-bottom: 1px solid rgba(255,255,255,0.05); padding: 8px; color: var(--accent-purple);">${log.value ? log.value + ' pkt' : ''}</td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        tbody.innerHTML = `<tr><td class="text-center text-red">Lỗi tải dữ liệu: ${e.message}</td></tr>`;
    }
}

async function loadRouting() {
    const tbody = document.getElementById('routingTable');
    tbody.innerHTML = '<tr><td colspan="5" class="text-center">Đang tải...</td></tr>';
    try {
        const routes = await apiRequest('routing');
        if (!routes || routes.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center">Chưa có luồng định tuyến nào.</td></tr>';
            return;
        }
        tbody.innerHTML = '';
        routes.forEach((rt, idx) => {
            const tr = document.createElement('tr');
            const typeBadge = rt.tunnel_type === 'wireguard' 
                ? '<span class="badge" style="background: #e67e22;">WireGuard</span>'
                : '<span class="badge" style="background: #3498db;">IPIP</span>';

            tr.innerHTML = `
                <td>${idx + 1}</td>
                <td><span class="badge badge-success">${rt.vip}</span></td>
                <td><code>${rt.backend_ip}</code></td>
                <td>${typeBadge}</td>
                <td><button class="btn btn-sm btn-danger" onclick="removeRoute('${rt.vip}', '${rt.backend_ip}', '${rt.tunnel_type}')"><i class="fa-solid fa-trash"></i> Xoá</button></td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="5" class="text-center text-red">Lỗi tải dữ liệu: ${e.message}</td></tr>`;
    }
}



// --- Hành động Sửa đổi Dữ liệu ---

async function addBlacklistIP() {
    const { value: target } = await Swal.fire({
        title: 'Chặn IP / Quốc Gia mới',
        input: 'text',
        inputLabel: 'Nhập IP, Subnet, hoặc Mã Quốc Gia',
        inputPlaceholder: 'Ví dụ: 192.168.1.100, 1.1.1.0/24, VN',
        showCancelButton: true
    });
    
    if (target) {
        Swal.fire({ title: 'Đang xử lý...', didOpen: () => Swal.showLoading() });
        try {
            const res = await apiRequest(`blacklist?target=${target}`, 'POST');
            Swal.fire('Thành công', res, 'success');
            loadBlacklist();
        } catch (e) {
            Swal.fire('Lỗi', e.message, 'error');
        }
    }
}

async function removeBlacklist(target) {
    if (confirm(`Bạn có chắc chắn muốn bỏ chặn ${target} không?`)) {
        Swal.fire({ title: 'Đang xử lý...', didOpen: () => Swal.showLoading() });
        try {
            const res = await apiRequest(`blacklist?target=${target}`, 'DELETE');
            Swal.fire('Thành công', res, 'success');
            loadBlacklist();
        } catch (e) {
            Swal.fire('Lỗi', e.message, 'error');
        }
    }
}

async function addWhitelistIP() {
    const { value: target } = await Swal.fire({
        title: 'Thêm IP / Quốc Gia Ưu tiên',
        input: 'text',
        inputLabel: 'Nhập IP, Subnet, hoặc Mã Quốc Gia',
        inputPlaceholder: 'Ví dụ: 8.8.8.8, 10.0.0.0/8, US',
        showCancelButton: true
    });
    
    if (target) {
        Swal.fire({ title: 'Đang xử lý...', didOpen: () => Swal.showLoading() });
        try {
            const res = await apiRequest(`whitelist?target=${target}`, 'POST');
            Swal.fire('Thành công', res, 'success');
            loadWhitelist();
        } catch (e) {
            Swal.fire('Lỗi', e.message, 'error');
        }
    }
}

async function removeWhitelistIP(target) {
    if (confirm(`Xoá ${target} khỏi danh sách ưu tiên?`)) {
        Swal.fire({ title: 'Đang xử lý...', didOpen: () => Swal.showLoading() });
        try {
            const res = await apiRequest(`whitelist?target=${target}`, 'DELETE');
            Swal.fire('Thành công', res, 'success');
            loadWhitelist();
        } catch (e) {
            Swal.fire('Lỗi', e.message, 'error');
        }
    }
}

async function addRoute() {
    const { value: formValues } = await Swal.fire({
        title: 'Thêm định tuyến Anti-DDoS',
        html:
            '<input id="swal-input1" class="swal2-input" placeholder="Front-end VIP (Ví dụ: 103.77...)" style="margin-bottom: 10px;">' +
            '<input id="swal-input2" class="swal2-input" placeholder="Backend IP (IP đích)" style="margin-bottom: 10px;">' +
            '<select id="swal-input3" class="swal2-input" style="height: auto; padding: 10px;">' +
            '  <option value="ipip">IPIP Tunnel (Dành cho máy chủ Linux)</option>' +
            '  <option value="wireguard">WireGuard (Dành cho máy chủ Windows)</option>' +
            '</select>',
        focusConfirm: false,
        showCancelButton: true,
        preConfirm: () => {
            return [
                document.getElementById('swal-input1').value,
                document.getElementById('swal-input2').value,
                document.getElementById('swal-input3').value
            ]
        }
    });

    if (formValues && formValues[0] && formValues[1]) {
        try {
            await apiRequest(`routing?vip=${formValues[0]}&backend=${formValues[1]}&type=${formValues[2]}`, 'POST');
            Swal.fire('Thành công', 'Đã thêm luật định tuyến', 'success');
            loadRouting();
        } catch (e) {
            Swal.fire('Lỗi', e.message, 'error');
        }
    }
}

async function removeRoute(vip, backend, type) {
    if (confirm(`Xoá luồng định tuyến cho VIP ${vip}?`)) {
        try {
            await apiRequest(`routing?vip=${vip}&backend=${backend}&type=${type}`, 'DELETE');
            loadRouting();
        } catch (e) {
            Swal.fire('Lỗi', e.message, 'error');
        }
    }
}

let currentGeoPolicy = 'blacklist';

async function addASN() {
    const isWhite = currentGeoPolicy === 'whitelist';
    const { value: asn } = await Swal.fire({
        title: isWhite ? 'Cho phép theo ASN' : 'Chặn theo ASN',
        input: 'text',
        inputLabel: 'Nhập mã ASN (ví dụ AS12345)',
        showCancelButton: true
    });
    if (asn) {
        try {
            const res = await apiRequest(`rules/asn?asn=${asn}`, 'POST');
            Swal.fire('Thành công', res, 'success');
            loadASN();
        } catch (e) {
            Swal.fire('Lỗi', e.message, 'error');
        }
    }
}

async function removeASN(asn) {
    const isWhite = currentGeoPolicy === 'whitelist';
    const actionText = isWhite ? 'loại bỏ ASN này khỏi danh sách cho phép' : 'bỏ chặn toàn bộ ASN';
    if (confirm(`Bạn có chắc muốn ${actionText} ${asn} không?`)) {
        try {
            await apiRequest(`rules/asn?asn=${asn}`, 'DELETE');
            loadASN();
        } catch (e) {
            Swal.fire('Lỗi', e.message, 'error');
        }
    }
}

async function addCountry() {
    const isWhite = currentGeoPolicy === 'whitelist';
    const { value: code } = await Swal.fire({
        title: isWhite ? 'Cho phép Quốc gia' : 'Chặn Quốc gia',
        input: 'text',
        inputLabel: 'Mã quốc gia (ISO 3166-1 alpha-2, VD: VN, US, CN)',
        inputPlaceholder: 'US',
        showCancelButton: true
    });

    if (code) {
        try {
            const res = await apiRequest(`rules/country?country=${code}`, 'POST');
            Swal.fire('Thành công', res, 'success');
            loadCountry();
        } catch (e) {
            Swal.fire('Lỗi', e.message, 'error');
        }
    }
}

async function removeCountry(country) {
    const isWhite = currentGeoPolicy === 'whitelist';
    const actionText = isWhite ? 'loại bỏ quốc gia này khỏi danh sách cho phép' : 'bỏ chặn toàn bộ quốc gia';
    if (confirm(`Bạn có chắc muốn ${actionText} ${country} không?`)) {
        try {
            await apiRequest(`rules/country?country=${country}`, 'DELETE');
            loadCountry();
        } catch (e) {
            Swal.fire('Lỗi', e.message, 'error');
        }
    }
}

async function setGeoPolicy(action) {
    if (confirm(`Bạn có chắc muốn đổi GeoIP Policy thành ${action.toUpperCase()} không?`)) {
        try {
            const res = await apiRequest(`rules/policy?action=${action}`, 'POST');
            Swal.fire('Thành công', res, 'success');
            loadGeoPolicy();
        } catch (e) {
            Swal.fire('Lỗi', e.message, 'error');
        }
    }
}

async function loadGeoPolicy() {
    try {
        const res = await apiRequest('rules/policy');
        if (res && res.policy) {
            currentGeoPolicy = res.policy;
            const isWhite = res.policy === 'whitelist';
            // Update titles
            document.getElementById('titleASN').innerHTML = isWhite ? '<i class="fa-solid fa-network-wired"></i> Cho phép theo ASN' : '<i class="fa-solid fa-network-wired"></i> Chặn theo ASN';
            document.getElementById('titleCountry').innerHTML = isWhite ? '<i class="fa-solid fa-globe"></i> Cho phép theo Quốc gia' : '<i class="fa-solid fa-globe"></i> Chặn theo Quốc gia';
            
            // Highlight active button
            document.getElementById('btnPolicyBlack').className = isWhite ? 'btn btn-sm btn-outline' : 'btn btn-sm btn-danger';
            document.getElementById('btnPolicyWhite').className = isWhite ? 'btn btn-sm btn-success' : 'btn btn-sm btn-outline';
        }
    } catch (e) {
        console.error("Lỗi khi tải GeoIP Policy:", e);
    }
}

// --- Utilities ---

function promptApiKey() {
    Swal.fire({
        title: 'Xác thực API',
        input: 'text',
        inputLabel: 'Vui lòng nhập API Key của Shield-Core',
        inputValue: apiKey,
        showCancelButton: true,
        confirmButtonText: 'Lưu & Kết nối'
    }).then((result) => {
        if (result.isConfirmed) {
            apiKey = result.value.trim();
            localStorage.setItem('shield_api_key', apiKey);
            startAutoRefresh();
        }
    });
}

function updateConnectionStatus(isOk) {
    const dot = document.getElementById('connDot');
    const txt = document.getElementById('connText');
    if (isOk) {
        dot.className = 'dot active';
        txt.innerText = 'Đã kết nối API';
    } else {
        dot.className = 'dot error';
        txt.innerText = 'Mất kết nối API';
    }
}

function formatUptime(seconds) {
    if (seconds < 60) return seconds + 's';
    const m = Math.floor(seconds / 60);
    if (m < 60) return m + 'm ' + (seconds % 60) + 's';
    const h = Math.floor(m / 60);
    return h + 'h ' + (m % 60) + 'm';
}

function animateValue(id, value) {
    const obj = document.getElementById(id);
    if (!obj) return;
    // Format numbers with commas
    obj.innerText = value.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}
