/**
 * SecureVault Backup Module
 * Handles Google Drive backup and local export/import
 */

const BackupModule = (() => {
    // Google Drive API configuration
    const GOOGLE_CLIENT_ID = '234745664114-4ljoufqemkpuvor7r7s1thhh2vcthirk.apps.googleusercontent.com';
    const GOOGLE_API_KEY = 'AIzaSyDqUoTa-EF-u-TpNPq7hgQX9sDb7wLpvYE';
    const DISCOVERY_DOCS = ['https://www.googleapis.com/discovery/v1/apis/drive/v3/rest'];
    const SCOPES = 'https://www.googleapis.com/auth/drive.file';

    const BACKUP_FOLDER_NAME = 'SecureVault_Backups';
    const BACKUP_FILE_PREFIX = 'securevault_backup_';
    const MAX_BACKUPS = 5;

    let isGapiLoaded = false;
    let isGisLoaded = false;
    let tokenClient = null;
    let accessToken = null;
    let userProfile = null;

    // ==================== GOOGLE DRIVE INTEGRATION (GIS) ====================

    /**
     * Initialize Google API client (GAPI for Drive API)
     * @returns {Promise<void>}
     */
    async function initGapi() {
        return new Promise((resolve, reject) => {
            if (typeof gapi === 'undefined') {
                reject(new Error('Google API not loaded'));
                return;
            }
            gapi.load('client', async () => {
                try {
                    await gapi.client.init({
                        apiKey: GOOGLE_API_KEY,
                        discoveryDocs: DISCOVERY_DOCS
                    });
                    isGapiLoaded = true;
                    resolve();
                } catch (error) {
                    console.error('GAPI init error:', error);
                    reject(error);
                }
            });
        });
    }

    /**
     * Initialize Google Identity Services (GIS) for OAuth
     * @returns {Promise<void>}
     */
    function initGis() {
        return new Promise((resolve, reject) => {
            if (typeof google === 'undefined' || !google.accounts) {
                reject(new Error('Google Identity Services not loaded'));
                return;
            }

            tokenClient = google.accounts.oauth2.initTokenClient({
                client_id: GOOGLE_CLIENT_ID,
                scope: SCOPES,
                callback: (response) => {
                    if (response.error) {
                        console.error('Token error:', response);
                        return;
                    }
                    accessToken = response.access_token;
                    // Fetch user profile
                    fetchUserProfile();
                }
            });

            isGisLoaded = true;
            resolve();
        });
    }

    /**
     * Fetch user profile from Google
     */
    async function fetchUserProfile() {
        if (!accessToken) return;

        try {
            const response = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
                headers: { 'Authorization': `Bearer ${accessToken}` }
            });
            userProfile = await response.json();
        } catch (error) {
            console.error('Failed to fetch user profile:', error);
        }
    }

    /**
     * Initialize Google Drive (both GAPI and GIS)
     * @returns {Promise<boolean>}
     */
    async function initGoogleDrive() {
        if (!GOOGLE_CLIENT_ID || !GOOGLE_API_KEY) {
            console.warn('Google Drive API credentials not configured');
            return false;
        }

        try {
            await initGapi();
            await initGis();
            return true;
        } catch (error) {
            console.error('Google Drive init error:', error);
            throw error;
        }
    }

    /**
     * Check if user is signed in to Google
     * @returns {boolean}
     */
    function isSignedIn() {
        return !!accessToken;
    }

    /**
     * Sign in to Google using GIS
     * @returns {Promise<void>}
     */
    async function signIn() {
        if (!isGapiLoaded) {
            await initGapi();
        }
        if (!isGisLoaded) {
            await initGis();
        }

        return new Promise((resolve, reject) => {
            tokenClient.callback = async (response) => {
                if (response.error) {
                    reject(response);
                    return;
                }
                accessToken = response.access_token;
                await fetchUserProfile();
                resolve();
            };

            if (accessToken === null) {
                // Prompt user to select account and consent
                tokenClient.requestAccessToken({ prompt: 'consent' });
            } else {
                // Skip account selection
                tokenClient.requestAccessToken({ prompt: '' });
            }
        });
    }

    /**
     * Sign out from Google
     */
    function signOut() {
        if (accessToken) {
            google.accounts.oauth2.revoke(accessToken, () => {
                accessToken = null;
                userProfile = null;
            });
        }
    }

    /**
     * Get signed-in user's email address
     * @returns {string|null} Email address or null if not signed in
     */
    function getSignedInUserEmail() {
        return userProfile ? userProfile.email : null;
    }

    /**
     * Get signed-in user's profile information
     * @returns {object|null} Profile info with name, email, imageUrl or null if not signed in
     */
    function getSignedInUserProfile() {
        if (!userProfile) return null;
        return {
            name: userProfile.name,
            email: userProfile.email,
            imageUrl: userProfile.picture
        };
    }

    /**
     * Get or create backup folder in Google Drive
     * @returns {Promise<string>} Folder ID
     */
    async function getOrCreateBackupFolder() {
        // Search for existing folder
        const response = await gapi.client.drive.files.list({
            q: `name='${BACKUP_FOLDER_NAME}' and mimeType='application/vnd.google-apps.folder' and trashed=false`,
            fields: 'files(id, name)'
        });

        if (response.result.files && response.result.files.length > 0) {
            return response.result.files[0].id;
        }

        // Create new folder
        const folderMetadata = {
            name: BACKUP_FOLDER_NAME,
            mimeType: 'application/vnd.google-apps.folder'
        };

        const folder = await gapi.client.drive.files.create({
            resource: folderMetadata,
            fields: 'id'
        });

        return folder.result.id;
    }

    /**
     * Upload backup to Google Drive
     * @param {object} backupData - Encrypted backup data
     * @returns {Promise<object>} Upload result
     */
    async function uploadToGoogleDrive(backupData) {
        if (!isSignedIn()) {
            throw new Error('Not signed in to Google Drive');
        }

        const folderId = await getOrCreateBackupFolder();
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const fileName = `${BACKUP_FILE_PREFIX}${timestamp}.json`;

        const file = new Blob([JSON.stringify(backupData)], { type: 'application/json' });

        const metadata = {
            name: fileName,
            mimeType: 'application/json',
            parents: [folderId]
        };

        const form = new FormData();
        form.append('metadata', new Blob([JSON.stringify(metadata)], { type: 'application/json' }));
        form.append('file', file);

        const response = await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,name,createdTime', {
            method: 'POST',
            headers: new Headers({ 'Authorization': 'Bearer ' + gapi.auth.getToken().access_token }),
            body: form
        });

        const result = await response.json();

        // Clean up old backups
        await cleanupOldBackups(folderId);

        return result;
    }

    /**
     * List backups from Google Drive
     * @returns {Promise<Array>}
     */
    async function listGoogleDriveBackups() {
        if (!isSignedIn()) {
            return [];
        }

        const folderId = await getOrCreateBackupFolder();

        const response = await gapi.client.drive.files.list({
            q: `'${folderId}' in parents and name contains '${BACKUP_FILE_PREFIX}' and trashed=false`,
            fields: 'files(id, name, createdTime, size)',
            orderBy: 'createdTime desc'
        });

        return response.result.files || [];
    }

    /**
     * Download backup from Google Drive
     * @param {string} fileId
     * @returns {Promise<object>}
     */
    async function downloadFromGoogleDrive(fileId) {
        const response = await gapi.client.drive.files.get({
            fileId: fileId,
            alt: 'media'
        });

        return JSON.parse(response.body);
    }

    /**
     * Delete old backups, keeping only MAX_BACKUPS
     * @param {string} folderId
     */
    async function cleanupOldBackups(folderId) {
        const backups = await listGoogleDriveBackups();

        if (backups.length > MAX_BACKUPS) {
            const toDelete = backups.slice(MAX_BACKUPS);

            for (const backup of toDelete) {
                await gapi.client.drive.files.delete({
                    fileId: backup.id
                });
            }
        }
    }

    // ==================== LOCAL EXPORT/IMPORT ====================

    /**
     * Export vault to encrypted JSON file
     * @param {object} backupData
     */
    function downloadAsFile(backupData) {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const fileName = `${BACKUP_FILE_PREFIX}${timestamp}.json`;

        const blob = new Blob([JSON.stringify(backupData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);

        const a = document.createElement('a');
        a.href = url;
        a.download = fileName;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    /**
     * Import from JSON file
     * @param {File} file
     * @returns {Promise<object>}
     */
    function importFromFile(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();

            reader.onload = (e) => {
                try {
                    const data = JSON.parse(e.target.result);
                    resolve(data);
                } catch (error) {
                    reject(new Error('Invalid backup file format'));
                }
            };

            reader.onerror = () => reject(new Error('Failed to read file'));
            reader.readAsText(file);
        });
    }

    // ==================== LASTPASS IMPORT ====================

    /**
     * Parse LastPass CSV export
     * @param {string} csvContent
     * @returns {Array<object>}
     */
    function parseLastPassCSV(csvContent) {
        const lines = csvContent.split('\n');
        const entries = [];

        // Skip header row
        for (let i = 1; i < lines.length; i++) {
            const line = lines[i].trim();
            if (!line) continue;

            // LastPass CSV format: url,username,password,totp,extra,name,grouping,fav
            const values = parseCSVLine(line);

            if (values.length >= 6) {
                entries.push({
                    name: values[5] || values[0] || 'Imported Entry',
                    url: values[0] || '',
                    username: values[1] || '',
                    password: values[2] || '',
                    notes: values[4] || '',
                    category: values[6] || 'Imported',
                    favorite: values[7] === '1'
                });
            }
        }

        return entries;
    }

    /**
     * Parse a single CSV line handling quoted values
     * @param {string} line
     * @returns {Array<string>}
     */
    function parseCSVLine(line) {
        const values = [];
        let current = '';
        let inQuotes = false;

        for (let i = 0; i < line.length; i++) {
            const char = line[i];

            if (char === '"') {
                inQuotes = !inQuotes;
            } else if (char === ',' && !inQuotes) {
                values.push(current.trim());
                current = '';
            } else {
                current += char;
            }
        }

        values.push(current.trim());
        return values;
    }

    /**
     * Import from LastPass CSV file
     * @param {File} file
     * @returns {Promise<Array>}
     */
    function importFromLastPass(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();

            reader.onload = (e) => {
                try {
                    const entries = parseLastPassCSV(e.target.result);
                    resolve(entries);
                } catch (error) {
                    reject(new Error('Failed to parse LastPass export: ' + error.message));
                }
            };

            reader.onerror = () => reject(new Error('Failed to read file'));
            reader.readAsText(file);
        });
    }

    // ==================== AUTO BACKUP ====================

    let autoBackupEnabled = false;
    let autoBackupInterval = null;

    /**
     * Enable auto backup
     * @param {number} intervalMinutes - Backup interval in minutes
     */
    function enableAutoBackup(intervalMinutes = 30) {
        if (autoBackupInterval) {
            clearInterval(autoBackupInterval);
        }

        autoBackupEnabled = true;
        autoBackupInterval = setInterval(async () => {
            if (isSignedIn()) {
                try {
                    const backupData = await StorageModule.exportForBackup();
                    await uploadToGoogleDrive(backupData);
                    console.log('Auto backup completed');
                } catch (error) {
                    console.error('Auto backup failed:', error);
                }
            }
        }, intervalMinutes * 60 * 1000);
    }

    /**
     * Disable auto backup
     */
    function disableAutoBackup() {
        autoBackupEnabled = false;
        if (autoBackupInterval) {
            clearInterval(autoBackupInterval);
            autoBackupInterval = null;
        }
    }

    /**
     * Check if Google Drive is configured
     * @returns {boolean}
     */
    function isGoogleDriveConfigured() {
        return !!(GOOGLE_CLIENT_ID && GOOGLE_API_KEY);
    }

    // Public API
    return {
        // Google Drive
        initGoogleDrive,
        isSignedIn,
        signIn,
        signOut,
        getSignedInUserEmail,
        getSignedInUserProfile,
        uploadToGoogleDrive,
        listGoogleDriveBackups,
        downloadFromGoogleDrive,
        isGoogleDriveConfigured,
        // Local
        downloadAsFile,
        importFromFile,
        // LastPass
        importFromLastPass,
        // Auto backup
        enableAutoBackup,
        disableAutoBackup,
        isAutoBackupEnabled: () => autoBackupEnabled
    };
})();

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = BackupModule;
}
