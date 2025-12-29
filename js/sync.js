/**
 * SecureVault Sync Module
 * Handles communication with the backend server for cross-device sync
 */

const SyncModule = (() => {
    // API base URL - auto-detect based on current location
    const API_BASE = window.location.origin;

    // Token storage key
    const TOKEN_KEY = 'securevault_token';
    const USER_EMAIL_KEY = 'securevault_user_email';
    const LAST_SYNC_KEY = 'securevault_last_sync';

    // ==================== TOKEN MANAGEMENT ====================

    function getToken() {
        return localStorage.getItem(TOKEN_KEY);
    }

    function setToken(token) {
        localStorage.setItem(TOKEN_KEY, token);
    }

    function clearToken() {
        localStorage.removeItem(TOKEN_KEY);
        localStorage.removeItem(USER_EMAIL_KEY);
        localStorage.removeItem(LAST_SYNC_KEY);
    }

    function getUserEmail() {
        return localStorage.getItem(USER_EMAIL_KEY);
    }

    function setUserEmail(email) {
        localStorage.setItem(USER_EMAIL_KEY, email);
    }

    function isLoggedIn() {
        return !!getToken();
    }

    // ==================== API HELPERS ====================

    async function apiRequest(endpoint, options = {}) {
        const token = getToken();
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers
        };

        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }

        const response = await fetch(`${API_BASE}${endpoint}`, {
            ...options,
            headers
        });

        if (!response.ok) {
            const error = await response.json().catch(() => ({ detail: 'Request failed' }));

            // For 401, clear token only if it's not a login/register request
            if (response.status === 401) {
                const isAuthEndpoint = endpoint === '/api/login' || endpoint === '/api/register';
                if (!isAuthEndpoint) {
                    clearToken();
                }
                throw new Error(error.detail || 'Authentication failed');
            }

            throw new Error(error.detail || 'Request failed');
        }

        // Handle empty responses
        const text = await response.text();
        return text ? JSON.parse(text) : null;
    }

    // ==================== AUTH ENDPOINTS ====================

    async function register(email, password) {
        const result = await apiRequest('/api/register', {
            method: 'POST',
            body: JSON.stringify({ email, password })
        });

        setToken(result.access_token);
        setUserEmail(email);
        return result;
    }

    async function login(email, password) {
        const result = await apiRequest('/api/login', {
            method: 'POST',
            body: JSON.stringify({ email, password })
        });

        setToken(result.access_token);
        setUserEmail(email);
        return result;
    }

    function logout() {
        clearToken();
    }

    async function getMe() {
        return await apiRequest('/api/me');
    }

    async function deleteAccount() {
        await apiRequest('/api/me', { method: 'DELETE' });
        clearToken();
    }

    // ==================== VAULT SYNC ====================

    async function getVault() {
        return await apiRequest('/api/vault');
    }

    async function saveVault(encryptedData) {
        const result = await apiRequest('/api/vault', {
            method: 'PUT',
            body: JSON.stringify({ data: encryptedData })
        });

        // Store current time (local) when sync succeeds for accurate display
        localStorage.setItem(LAST_SYNC_KEY, new Date().toISOString());

        return result;
    }

    async function syncVault(encryptedData) {
        const lastSync = localStorage.getItem(LAST_SYNC_KEY);

        const result = await apiRequest('/api/sync', {
            method: 'POST',
            body: JSON.stringify({
                data: encryptedData,
                last_sync: lastSync
            })
        });

        // Store current time (local) when sync succeeds for accurate display
        localStorage.setItem(LAST_SYNC_KEY, new Date().toISOString());

        return result;
    }

    async function deleteVault() {
        return await apiRequest('/api/vault', { method: 'DELETE' });
    }

    // ==================== SYNC HELPERS ====================

    function getLastSyncTime() {
        const lastSync = localStorage.getItem(LAST_SYNC_KEY);
        return lastSync ? new Date(lastSync) : null;
    }

    function formatSyncTime(date) {
        if (!date) return 'Never';
        const now = new Date();
        const diff = now - date;

        if (diff < 60000) return 'Just now';
        if (diff < 3600000) return `${Math.floor(diff / 60000)} minutes ago`;
        if (diff < 86400000) return `${Math.floor(diff / 3600000)} hours ago`;
        return date.toLocaleDateString();
    }

    // ==================== AUTO SYNC ====================

    let autoSyncEnabled = false;
    let autoSyncInterval = null;
    let syncCallback = null;

    function enableAutoSync(callback, intervalMs = 30000) {
        syncCallback = callback;
        autoSyncEnabled = true;

        if (autoSyncInterval) {
            clearInterval(autoSyncInterval);
        }

        autoSyncInterval = setInterval(async () => {
            if (isLoggedIn() && syncCallback) {
                try {
                    await syncCallback();
                } catch (error) {
                    console.error('Auto sync failed:', error);
                }
            }
        }, intervalMs);
    }

    function disableAutoSync() {
        autoSyncEnabled = false;
        if (autoSyncInterval) {
            clearInterval(autoSyncInterval);
            autoSyncInterval = null;
        }
    }

    // Public API
    return {
        // Auth
        register,
        login,
        logout,
        isLoggedIn,
        getMe,
        deleteAccount,
        getUserEmail,

        // Vault
        getVault,
        saveVault,
        syncVault,
        deleteVault,

        // Sync
        getLastSyncTime,
        formatSyncTime,
        enableAutoSync,
        disableAutoSync,

        // Token
        getToken,
        clearToken
    };
})();

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SyncModule;
}
