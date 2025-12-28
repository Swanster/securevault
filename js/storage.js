/**
 * SecureVault Storage Module
 * Handles IndexedDB operations for encrypted password storage
 */

const StorageModule = (() => {
    const DB_NAME = 'SecureVault';
    const DB_VERSION = 1;
    let db = null;

    /**
     * Initialize the database
     * @returns {Promise<IDBDatabase>}
     */
    async function init() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open(DB_NAME, DB_VERSION);

            request.onerror = () => reject(request.error);
            request.onsuccess = () => {
                db = request.result;
                resolve(db);
            };

            request.onupgradeneeded = (event) => {
                const database = event.target.result;

                // Vault store - encrypted password entries
                if (!database.objectStoreNames.contains('vault')) {
                    const vaultStore = database.createObjectStore('vault', { keyPath: 'id' });
                    vaultStore.createIndex('category', 'category', { unique: false });
                    vaultStore.createIndex('createdAt', 'createdAt', { unique: false });
                    vaultStore.createIndex('updatedAt', 'updatedAt', { unique: false });
                }

                // Settings store - app configuration
                if (!database.objectStoreNames.contains('settings')) {
                    database.createObjectStore('settings', { keyPath: 'key' });
                }

                // Backup store - backup metadata
                if (!database.objectStoreNames.contains('backups')) {
                    const backupStore = database.createObjectStore('backups', { keyPath: 'id' });
                    backupStore.createIndex('timestamp', 'timestamp', { unique: false });
                }
            };
        });
    }

    /**
     * Ensure database is initialized
     */
    async function ensureDB() {
        if (!db) {
            await init();
        }
        return db;
    }

    // ==================== SETTINGS OPERATIONS ====================

    /**
     * Get a setting value
     * @param {string} key
     * @returns {Promise<any>}
     */
    async function getSetting(key) {
        await ensureDB();
        return new Promise((resolve, reject) => {
            const transaction = db.transaction(['settings'], 'readonly');
            const store = transaction.objectStore('settings');
            const request = store.get(key);

            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve(request.result?.value);
        });
    }

    /**
     * Set a setting value
     * @param {string} key
     * @param {any} value
     */
    async function setSetting(key, value) {
        await ensureDB();
        return new Promise((resolve, reject) => {
            const transaction = db.transaction(['settings'], 'readwrite');
            const store = transaction.objectStore('settings');
            const request = store.put({ key, value });

            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve();
        });
    }

    /**
     * Delete a setting
     * @param {string} key
     */
    async function deleteSetting(key) {
        await ensureDB();
        return new Promise((resolve, reject) => {
            const transaction = db.transaction(['settings'], 'readwrite');
            const store = transaction.objectStore('settings');
            const request = store.delete(key);

            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve();
        });
    }

    // ==================== VAULT OPERATIONS ====================

    /**
     * Generate unique ID
     * @returns {string}
     */
    function generateId() {
        return Date.now().toString(36) + Math.random().toString(36).substr(2);
    }

    /**
     * Save encrypted vault data
     * @param {object} encryptedData - {iv, ciphertext}
     */
    async function saveVaultData(encryptedData) {
        await setSetting('vault_data', encryptedData);
    }

    /**
     * Get encrypted vault data
     * @returns {Promise<object|null>}
     */
    async function getVaultData() {
        return await getSetting('vault_data');
    }

    /**
     * Save an individual encrypted entry (for quick access)
     * @param {object} entry - Entry with encrypted data
     */
    async function saveEntry(entry) {
        await ensureDB();
        return new Promise((resolve, reject) => {
            const transaction = db.transaction(['vault'], 'readwrite');
            const store = transaction.objectStore('vault');

            if (!entry.id) {
                entry.id = generateId();
            }
            entry.updatedAt = Date.now();
            if (!entry.createdAt) {
                entry.createdAt = entry.updatedAt;
            }

            const request = store.put(entry);
            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve(entry);
        });
    }

    /**
     * Get all entries from vault
     * @returns {Promise<Array>}
     */
    async function getAllEntries() {
        await ensureDB();
        return new Promise((resolve, reject) => {
            const transaction = db.transaction(['vault'], 'readonly');
            const store = transaction.objectStore('vault');
            const request = store.getAll();

            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve(request.result || []);
        });
    }

    /**
     * Get entry by ID
     * @param {string} id
     * @returns {Promise<object|null>}
     */
    async function getEntry(id) {
        await ensureDB();
        return new Promise((resolve, reject) => {
            const transaction = db.transaction(['vault'], 'readonly');
            const store = transaction.objectStore('vault');
            const request = store.get(id);

            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve(request.result);
        });
    }

    /**
     * Delete entry by ID
     * @param {string} id
     */
    async function deleteEntry(id) {
        await ensureDB();
        return new Promise((resolve, reject) => {
            const transaction = db.transaction(['vault'], 'readwrite');
            const store = transaction.objectStore('vault');
            const request = store.delete(id);

            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve();
        });
    }

    /**
     * Clear all entries
     */
    async function clearVault() {
        await ensureDB();
        return new Promise((resolve, reject) => {
            const transaction = db.transaction(['vault'], 'readwrite');
            const store = transaction.objectStore('vault');
            const request = store.clear();

            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve();
        });
    }

    /**
     * Get entries by category
     * @param {string} category
     * @returns {Promise<Array>}
     */
    async function getEntriesByCategory(category) {
        await ensureDB();
        return new Promise((resolve, reject) => {
            const transaction = db.transaction(['vault'], 'readonly');
            const store = transaction.objectStore('vault');
            const index = store.index('category');
            const request = index.getAll(category);

            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve(request.result || []);
        });
    }

    // ==================== BACKUP OPERATIONS ====================

    /**
     * Save backup metadata
     * @param {object} backup
     */
    async function saveBackupMeta(backup) {
        await ensureDB();
        return new Promise((resolve, reject) => {
            const transaction = db.transaction(['backups'], 'readwrite');
            const store = transaction.objectStore('backups');

            if (!backup.id) {
                backup.id = generateId();
            }
            backup.timestamp = Date.now();

            const request = store.put(backup);
            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve(backup);
        });
    }

    /**
     * Get all backup metadata
     * @returns {Promise<Array>}
     */
    async function getAllBackups() {
        await ensureDB();
        return new Promise((resolve, reject) => {
            const transaction = db.transaction(['backups'], 'readonly');
            const store = transaction.objectStore('backups');
            const request = store.getAll();

            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve(request.result || []);
        });
    }

    /**
     * Export all data for backup
     * @returns {Promise<object>}
     */
    async function exportForBackup() {
        const vaultData = await getVaultData();
        const entries = await getAllEntries();
        const salt = await getSetting('salt');
        const verificationHash = await getSetting('verificationHash');
        const passwordHint = await getSetting('passwordHint');

        return {
            version: '1.0',
            exportedAt: new Date().toISOString(),
            salt,
            verificationHash,
            passwordHint,
            vaultData,
            entries
        };
    }

    /**
     * Import data from backup
     * @param {object} backupData
     */
    async function importFromBackup(backupData) {
        if (backupData.salt) {
            await setSetting('salt', backupData.salt);
        }
        if (backupData.verificationHash) {
            await setSetting('verificationHash', backupData.verificationHash);
        }
        if (backupData.passwordHint) {
            await setSetting('passwordHint', backupData.passwordHint);
        }
        if (backupData.vaultData) {
            await saveVaultData(backupData.vaultData);
        }
        if (backupData.entries && Array.isArray(backupData.entries)) {
            await clearVault();
            for (const entry of backupData.entries) {
                await saveEntry(entry);
            }
        }
    }

    /**
     * Check if vault exists (has been set up)
     * @returns {Promise<boolean>}
     */
    async function vaultExists() {
        const salt = await getSetting('salt');
        const hash = await getSetting('verificationHash');
        return !!(salt && hash);
    }

    /**
     * Clear all data (full reset)
     */
    async function clearAllData() {
        await ensureDB();

        const stores = ['vault', 'settings', 'backups'];

        return new Promise((resolve, reject) => {
            const transaction = db.transaction(stores, 'readwrite');

            stores.forEach(storeName => {
                transaction.objectStore(storeName).clear();
            });

            transaction.oncomplete = () => resolve();
            transaction.onerror = () => reject(transaction.error);
        });
    }

    // Public API
    return {
        init,
        generateId,
        // Settings
        getSetting,
        setSetting,
        deleteSetting,
        // Vault
        saveVaultData,
        getVaultData,
        saveEntry,
        getAllEntries,
        getEntry,
        deleteEntry,
        clearVault,
        getEntriesByCategory,
        // Backup
        saveBackupMeta,
        getAllBackups,
        exportForBackup,
        importFromBackup,
        // Utility
        vaultExists,
        clearAllData
    };
})();

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = StorageModule;
}
