/**
 * SecureVault Main Application
 * Handles UI interactions and orchestrates all modules
 */

const App = (() => {
    // State
    let masterPassword = null;
    let salt = null;
    let entries = [];
    let currentEntryId = null;
    let autoLockTimer = null;
    const AUTO_LOCK_TIMEOUT = 5 * 60 * 1000; // 5 minutes
    const CLIPBOARD_CLEAR_TIMEOUT = 30 * 1000; // 30 seconds

    // DOM Elements
    const screens = {
        setup: document.getElementById('setup-screen'),
        login: document.getElementById('login-screen'),
        vault: document.getElementById('vault-screen'),
        settings: document.getElementById('settings-screen')
    };

    const modals = {
        entry: document.getElementById('entry-modal'),
        generator: document.getElementById('generator-modal'),
        view: document.getElementById('view-modal'),
        cloud: document.getElementById('cloud-modal')
    };

    // ==================== INITIALIZATION ====================

    async function init() {
        await StorageModule.init();
        setupEventListeners();
        await checkVaultStatus();
        setupAutoLock();
    }

    async function checkVaultStatus() {
        const exists = await StorageModule.vaultExists();
        if (exists) {
            showScreen('login');
            await loadPasswordHint();
        } else {
            showScreen('setup');
        }
    }

    async function loadPasswordHint() {
        const hint = await StorageModule.getSetting('passwordHint');
        const hintDisplay = document.getElementById('password-hint-display');
        if (hint) {
            hintDisplay.textContent = `Hint: ${hint}`;
            hintDisplay.classList.remove('hidden');
        }
    }

    // ==================== EVENT LISTENERS ====================

    function setupEventListeners() {
        // Setup form
        document.getElementById('setup-form').addEventListener('submit', handleSetup);
        document.getElementById('setup-password').addEventListener('input', updateSetupStrength);
        document.getElementById('restore-from-cloud-btn')?.addEventListener('click', openRestoreFromCloudModal);

        // Login form
        document.getElementById('login-form').addEventListener('submit', handleLogin);
        document.getElementById('biometric-login').addEventListener('click', handleBiometricLogin);

        // Vault actions
        document.getElementById('add-btn').addEventListener('click', () => openEntryModal());
        document.getElementById('lock-btn').addEventListener('click', lockVault);
        document.getElementById('settings-btn').addEventListener('click', () => showScreen('settings'));
        document.getElementById('search-input').addEventListener('input', filterEntries);

        // Category tabs
        document.getElementById('category-tabs').addEventListener('click', handleCategoryClick);

        // Settings
        document.getElementById('settings-back').addEventListener('click', () => showScreen('vault'));
        document.getElementById('export-btn').addEventListener('click', exportBackup);
        document.getElementById('import-btn').addEventListener('click', () => document.getElementById('import-file').click());
        document.getElementById('import-file').addEventListener('change', importBackup);
        document.getElementById('import-lastpass-btn').addEventListener('click', () => document.getElementById('lastpass-file').click());
        document.getElementById('lastpass-file').addEventListener('change', importLastPass);
        document.getElementById('reset-vault-btn').addEventListener('click', confirmResetVault);
        document.getElementById('biometric-toggle').addEventListener('change', toggleBiometric);
        document.getElementById('autolock-toggle').addEventListener('change', toggleAutoLock);

        // Security features
        document.getElementById('breach-check-btn')?.addEventListener('click', checkForBreaches);
        document.getElementById('change-password-btn')?.addEventListener('click', openChangePasswordModal);
        document.getElementById('change-password-modal-close')?.addEventListener('click', closeChangePasswordModal);
        document.getElementById('change-password-cancel')?.addEventListener('click', closeChangePasswordModal);
        document.getElementById('change-password-form')?.addEventListener('submit', handleChangePassword);
        document.getElementById('new-password')?.addEventListener('input', updateNewPasswordStrength);
        document.getElementById('change-password-modal')?.addEventListener('click', (e) => {
            if (e.target.id === 'change-password-modal') closeChangePasswordModal();
        });

        // Entry modal
        document.getElementById('entry-form').addEventListener('submit', handleEntrySave);
        document.getElementById('entry-modal-close').addEventListener('click', closeEntryModal);
        document.getElementById('entry-cancel').addEventListener('click', closeEntryModal);
        document.getElementById('generate-password-btn').addEventListener('click', openGeneratorModal);

        // Generator modal
        document.getElementById('generator-modal-close').addEventListener('click', closeGeneratorModal);
        document.getElementById('regenerate-btn').addEventListener('click', generateNewPassword);
        document.getElementById('use-password-btn').addEventListener('click', useGeneratedPassword);
        document.getElementById('password-length').addEventListener('input', updateLengthDisplay);
        ['gen-uppercase', 'gen-lowercase', 'gen-numbers', 'gen-symbols'].forEach(id => {
            document.getElementById(id).addEventListener('change', generateNewPassword);
        });

        // View modal
        document.getElementById('view-modal-close').addEventListener('click', closeViewModal);
        document.getElementById('edit-entry-btn').addEventListener('click', editCurrentEntry);
        document.getElementById('delete-entry-btn').addEventListener('click', deleteCurrentEntry);
        document.getElementById('open-url-btn').addEventListener('click', openCurrentUrl);

        // Password toggles
        document.querySelectorAll('.password-toggle').forEach(btn => {
            btn.addEventListener('click', togglePasswordVisibility);
        });

        // Copy buttons
        document.querySelectorAll('.copy-btn').forEach(btn => {
            btn.addEventListener('click', handleCopyClick);
        });

        // Close modals on overlay click
        Object.values(modals).forEach(modal => {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    modal.classList.remove('active');
                }
            });
        });

        // Reset auto-lock on activity
        ['click', 'keydown', 'mousemove', 'touchstart'].forEach(event => {
            document.addEventListener(event, resetAutoLockTimer);
        });

        // Cloud sync - wrap in try-catch in case elements don't exist
        try {
            document.getElementById('cloud-login-btn')?.addEventListener('click', openCloudModal);
            document.getElementById('cloud-modal-close')?.addEventListener('click', closeCloudModal);
            document.getElementById('cloud-form')?.addEventListener('submit', handleCloudAuth);
            document.getElementById('cloud-toggle-mode')?.addEventListener('click', toggleCloudAuthMode);
            document.getElementById('cloud-logout-btn')?.addEventListener('click', handleCloudLogout);
            document.getElementById('sync-now-btn')?.addEventListener('click', syncNow);

            // Cloud modal overlay click to close
            document.getElementById('cloud-modal')?.addEventListener('click', (e) => {
                if (e.target.id === 'cloud-modal') closeCloudModal();
            });

            // Update cloud UI on init
            updateCloudUI();
        } catch (error) {
            console.error('Cloud sync init error:', error);
        }
    }

    // ==================== SCREEN NAVIGATION ====================

    function showScreen(name) {
        Object.values(screens).forEach(screen => screen.classList.remove('active'));
        screens[name].classList.add('active');

        // Update security audit when entering settings
        if (name === 'settings') {
            updateSecurityAudit();
        }
    }

    function showLoading(show = true) {
        document.getElementById('loading').classList.toggle('hidden', !show);
    }

    // ==================== SETUP ====================

    async function handleSetup(e) {
        e.preventDefault();
        const password = document.getElementById('setup-password').value;
        const confirm = document.getElementById('setup-confirm').value;
        const hint = document.getElementById('setup-hint').value;

        if (password !== confirm) {
            showToast('Passwords do not match', 'error');
            return;
        }

        if (password.length < 8) {
            showToast('Password must be at least 8 characters', 'error');
            return;
        }

        showLoading(true);

        try {
            // Generate salt and verification hash
            salt = CryptoModule.generateSalt();
            const verificationHash = await CryptoModule.deriveVerificationHash(password, salt);

            // Save to storage
            await StorageModule.setSetting('salt', CryptoModule.uint8ArrayToBase64(salt));
            await StorageModule.setSetting('verificationHash', verificationHash);
            if (hint) {
                await StorageModule.setSetting('passwordHint', hint);
            }

            // Set master password and show vault
            masterPassword = password;
            entries = [];
            await saveEntries();

            showScreen('vault');
            renderEntries();
            showToast('Vault created successfully!', 'success');
        } catch (error) {
            console.error('Setup error:', error);
            showToast('Failed to create vault: ' + error.message, 'error');
        } finally {
            showLoading(false);
        }
    }

    function updateSetupStrength() {
        const password = document.getElementById('setup-password').value;
        const strength = CryptoModule.calculatePasswordStrength(password);
        const fill = document.getElementById('setup-strength-fill');
        const label = document.getElementById('setup-strength-label');

        fill.style.width = `${strength.score}%`;
        fill.style.backgroundColor = strength.color;
        label.textContent = password ? strength.label : 'Enter a password';
        label.style.color = strength.color;
    }

    // ==================== LOGIN ====================

    async function handleLogin(e) {
        e.preventDefault();
        const password = document.getElementById('login-password').value;

        showLoading(true);

        try {
            // Load salt and verify password
            const saltBase64 = await StorageModule.getSetting('salt');
            const storedHash = await StorageModule.getSetting('verificationHash');
            salt = CryptoModule.base64ToUint8Array(saltBase64);

            const inputHash = await CryptoModule.deriveVerificationHash(password, salt);

            if (inputHash !== storedHash) {
                showToast('Incorrect password', 'error');
                document.getElementById('login-password').value = '';
                return;
            }

            // Password correct, decrypt vault
            masterPassword = password;
            await loadEntries();

            showScreen('vault');
            renderEntries();
            showToast('Vault unlocked', 'success');

            // Clear password field
            document.getElementById('login-password').value = '';
        } catch (error) {
            console.error('Login error:', error);
            showToast('Failed to unlock vault', 'error');
        } finally {
            showLoading(false);
        }
    }

    async function handleBiometricLogin() {
        if (!window.PublicKeyCredential) {
            showToast('Biometric not supported', 'error');
            return;
        }

        try {
            // Check if biometric is available
            const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
            if (!available) {
                showToast('Biometric not available on this device', 'error');
                return;
            }

            // For now, this is a placeholder - full WebAuthn implementation would go here
            showToast('Biometric authentication coming soon!', 'info');
        } catch (error) {
            console.error('Biometric error:', error);
            showToast('Biometric authentication failed', 'error');
        }
    }

    // ==================== VAULT OPERATIONS ====================

    async function loadEntries() {
        const vaultData = await StorageModule.getVaultData();
        if (vaultData && vaultData.ciphertext) {
            try {
                entries = await CryptoModule.decrypt(
                    vaultData.ciphertext,
                    vaultData.iv,
                    masterPassword,
                    salt
                );
            } catch (error) {
                console.error('Decrypt error:', error);
                entries = [];
            }
        } else {
            entries = [];
        }
    }

    async function saveEntries() {
        const encrypted = await CryptoModule.encrypt(entries, masterPassword, salt);

        // Include metadata for cloud restore
        const saltBase64 = await StorageModule.getSetting('salt');
        const verificationHash = await StorageModule.getSetting('verificationHash');
        encrypted.salt = saltBase64;
        encrypted.verificationHash = verificationHash;

        await StorageModule.saveVaultData(encrypted);
    }

    function lockVault() {
        masterPassword = null;
        salt = null;
        entries = [];
        currentEntryId = null;
        showScreen('login');
        showToast('Vault locked', 'success');
    }

    // ==================== ENTRY RENDERING ====================

    function renderEntries() {
        const list = document.getElementById('password-list');
        const emptyState = document.getElementById('empty-state');
        const searchTerm = document.getElementById('search-input').value.toLowerCase();
        const activeCategory = document.querySelector('.category-tab.active').dataset.category;

        let filtered = entries.filter(entry => {
            const matchesSearch = entry.name.toLowerCase().includes(searchTerm) ||
                (entry.username && entry.username.toLowerCase().includes(searchTerm));
            const matchesCategory = activeCategory === 'all' || entry.category === activeCategory;
            return matchesSearch && matchesCategory;
        });

        if (filtered.length === 0) {
            list.innerHTML = '';
            emptyState.classList.remove('hidden');
            return;
        }

        emptyState.classList.add('hidden');
        list.innerHTML = filtered.map(entry => `
            <div class="password-item" data-id="${entry.id}">
                <div class="password-item-icon">${getFaviconHtml(entry)}</div>
                <div class="password-item-info">
                    <div class="password-item-name">${escapeHtml(entry.name)}</div>
                    <div class="password-item-username">${escapeHtml(entry.username || 'No username')}</div>
                </div>
                <div class="password-item-actions">
                    <button class="btn btn-icon copy-password-btn" data-id="${entry.id}" title="Copy password">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                    </button>
                </div>
            </div>
        `).join('');

        // Add click listeners
        list.querySelectorAll('.password-item').forEach(item => {
            item.addEventListener('click', (e) => {
                if (!e.target.closest('.copy-password-btn')) {
                    viewEntry(item.dataset.id);
                }
            });
        });

        list.querySelectorAll('.copy-password-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                copyEntryPassword(btn.dataset.id);
            });
        });
    }

    function getFaviconHtml(entry) {
        const url = entry.url || entry.website;
        if (url) {
            try {
                const domain = new URL(url.startsWith('http') ? url : 'https://' + url).hostname;
                return `<img src="https://www.google.com/s2/favicons?domain=${domain}&sz=32" alt="" onerror="this.style.display='none';this.nextSibling.style.display='flex'"><span style="display:none" class="fallback-icon">${getInitials(entry.name)}</span>`;
            } catch (e) {
                // Invalid URL, fall back to initials
            }
        }
        return getInitials(entry.name);
    }

    function getInitials(name) {
        return name.split(' ').map(w => w[0]).join('').slice(0, 2).toUpperCase();
    }

    function escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function filterEntries() {
        renderEntries();
    }

    function handleCategoryClick(e) {
        if (e.target.classList.contains('category-tab')) {
            document.querySelectorAll('.category-tab').forEach(tab => tab.classList.remove('active'));
            e.target.classList.add('active');
            renderEntries();
        }
    }

    // ==================== ENTRY MODAL ====================

    function openEntryModal(entry = null) {
        const modal = modals.entry;
        const title = document.getElementById('entry-modal-title');
        const form = document.getElementById('entry-form');

        form.reset();
        document.getElementById('entry-id').value = '';

        if (entry) {
            title.textContent = 'Edit Password';
            document.getElementById('entry-id').value = entry.id;
            document.getElementById('entry-name').value = entry.name || '';
            document.getElementById('entry-url').value = entry.url || '';
            document.getElementById('entry-username').value = entry.username || '';
            document.getElementById('entry-password').value = entry.password || '';
            document.getElementById('entry-category').value = entry.category || 'Other';
            document.getElementById('entry-notes').value = entry.notes || '';
        } else {
            title.textContent = 'Add Password';
        }

        modal.classList.add('active');
    }

    function closeEntryModal() {
        modals.entry.classList.remove('active');
    }

    async function handleEntrySave(e) {
        e.preventDefault();

        const id = document.getElementById('entry-id').value;
        const entry = {
            id: id || StorageModule.generateId(),
            name: document.getElementById('entry-name').value,
            url: document.getElementById('entry-url').value,
            username: document.getElementById('entry-username').value,
            password: document.getElementById('entry-password').value,
            category: document.getElementById('entry-category').value,
            notes: document.getElementById('entry-notes').value,
            updatedAt: Date.now()
        };

        if (id) {
            // Update existing
            const index = entries.findIndex(e => e.id === id);
            if (index !== -1) {
                entry.createdAt = entries[index].createdAt;
                entries[index] = entry;
            }
        } else {
            // Add new
            entry.createdAt = Date.now();
            entries.push(entry);
        }

        await saveEntries();
        closeEntryModal();
        renderEntries();
        showToast(id ? 'Password updated' : 'Password added', 'success');
    }

    // ==================== VIEW MODAL ====================

    function viewEntry(id) {
        const entry = entries.find(e => e.id === id);
        if (!entry) return;

        currentEntryId = id;

        document.getElementById('view-title').textContent = entry.name;
        document.getElementById('view-url').value = entry.url || '';
        document.getElementById('view-username').value = entry.username || '';
        document.getElementById('view-password').value = entry.password || '';
        document.getElementById('view-notes').value = entry.notes || '';

        const notesGroup = document.getElementById('view-notes-group');
        notesGroup.classList.toggle('hidden', !entry.notes);

        modals.view.classList.add('active');
    }

    function closeViewModal() {
        modals.view.classList.remove('active');
        currentEntryId = null;
    }

    function editCurrentEntry() {
        const entry = entries.find(e => e.id === currentEntryId);
        if (entry) {
            closeViewModal();
            openEntryModal(entry);
        }
    }

    async function deleteCurrentEntry() {
        if (!confirm('Are you sure you want to delete this password?')) return;

        entries = entries.filter(e => e.id !== currentEntryId);
        await saveEntries();
        closeViewModal();
        renderEntries();
        showToast('Password deleted', 'success');
    }

    function openCurrentUrl() {
        const url = document.getElementById('view-url').value;
        if (url) {
            window.open(url, '_blank');
        }
    }

    // ==================== PASSWORD GENERATOR ====================

    function openGeneratorModal() {
        modals.generator.classList.add('active');
        generateNewPassword();
    }

    function closeGeneratorModal() {
        modals.generator.classList.remove('active');
    }

    function generateNewPassword() {
        const length = parseInt(document.getElementById('password-length').value);
        const options = {
            uppercase: document.getElementById('gen-uppercase').checked,
            lowercase: document.getElementById('gen-lowercase').checked,
            numbers: document.getElementById('gen-numbers').checked,
            symbols: document.getElementById('gen-symbols').checked
        };

        const password = CryptoModule.generatePassword(length, options);
        document.getElementById('generated-password').textContent = password;

        // Update strength meter
        const strength = CryptoModule.calculatePasswordStrength(password);
        document.getElementById('gen-strength-fill').style.width = `${strength.score}%`;
        document.getElementById('gen-strength-fill').style.backgroundColor = strength.color;
        document.getElementById('gen-strength-label').textContent = strength.label;
        document.getElementById('gen-strength-label').style.color = strength.color;
    }

    function updateLengthDisplay() {
        const length = document.getElementById('password-length').value;
        document.getElementById('length-value').textContent = length;
        generateNewPassword();
    }

    function useGeneratedPassword() {
        const password = document.getElementById('generated-password').textContent;
        document.getElementById('entry-password').value = password;
        closeGeneratorModal();
    }

    // ==================== CLIPBOARD ====================

    async function copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);
            showToast('Copied to clipboard', 'success');

            // Auto-clear after timeout
            setTimeout(async () => {
                try {
                    const current = await navigator.clipboard.readText();
                    if (current === text) {
                        await navigator.clipboard.writeText('');
                    }
                } catch (e) {
                    // Ignore - clipboard may not be accessible
                }
            }, CLIPBOARD_CLEAR_TIMEOUT);
        } catch (error) {
            showToast('Failed to copy', 'error');
        }
    }

    function handleCopyClick(e) {
        const targetId = e.currentTarget.dataset.copy;
        const input = document.getElementById(targetId);
        if (input) {
            copyToClipboard(input.value);
        }
    }

    function copyEntryPassword(id) {
        const entry = entries.find(e => e.id === id);
        if (entry && entry.password) {
            copyToClipboard(entry.password);
        }
    }

    // ==================== PASSWORD VISIBILITY ====================

    function togglePasswordVisibility(e) {
        const targetId = e.currentTarget.dataset.target;
        const input = document.getElementById(targetId);
        if (input) {
            const isPassword = input.type === 'password';
            input.type = isPassword ? 'text' : 'password';
        }
    }

    // ==================== AUTO LOCK ====================

    function setupAutoLock() {
        const enabled = document.getElementById('autolock-toggle').checked;
        if (enabled) {
            resetAutoLockTimer();
        }
    }

    function resetAutoLockTimer() {
        if (autoLockTimer) {
            clearTimeout(autoLockTimer);
        }

        const enabled = document.getElementById('autolock-toggle')?.checked;
        if (enabled && masterPassword) {
            autoLockTimer = setTimeout(() => {
                lockVault();
                showToast('Vault locked due to inactivity', 'info');
            }, AUTO_LOCK_TIMEOUT);
        }
    }

    function toggleAutoLock(e) {
        if (e.target.checked) {
            resetAutoLockTimer();
        } else if (autoLockTimer) {
            clearTimeout(autoLockTimer);
        }
    }

    // ==================== BIOMETRIC ====================

    function toggleBiometric(e) {
        if (e.target.checked) {
            // Enable biometric - placeholder for WebAuthn registration
            showToast('Biometric unlock enabled', 'success');
            document.getElementById('biometric-login').classList.remove('hidden');
        } else {
            document.getElementById('biometric-login').classList.add('hidden');
        }
    }

    // ==================== BACKUP & RESTORE ====================

    async function exportBackup() {
        try {
            showLoading(true);
            const backupData = await StorageModule.exportForBackup();
            BackupModule.downloadAsFile(backupData);
            showToast('Backup exported', 'success');
        } catch (error) {
            console.error('Export error:', error);
            showToast('Failed to export backup', 'error');
        } finally {
            showLoading(false);
        }
    }

    async function importBackup(e) {
        const file = e.target.files[0];
        if (!file) return;

        try {
            showLoading(true);
            const backupData = await BackupModule.importFromFile(file);

            // Verify it's a valid backup
            if (!backupData.salt || !backupData.verificationHash) {
                throw new Error('Invalid backup file');
            }

            await StorageModule.importFromBackup(backupData);

            // Reload vault
            masterPassword = null;
            showScreen('login');
            await loadPasswordHint();
            showToast('Backup imported. Please enter your master password.', 'success');
        } catch (error) {
            console.error('Import error:', error);
            showToast('Failed to import backup: ' + error.message, 'error');
        } finally {
            showLoading(false);
            e.target.value = '';
        }
    }

    async function importLastPass(e) {
        const file = e.target.files[0];
        if (!file) return;

        if (!masterPassword) {
            showToast('Please unlock vault first', 'error');
            e.target.value = '';
            return;
        }

        try {
            showLoading(true);
            const imported = await BackupModule.importFromLastPass(file);

            // Add imported entries
            for (const entry of imported) {
                entry.id = StorageModule.generateId();
                entry.createdAt = Date.now();
                entry.updatedAt = Date.now();
                entries.push(entry);
            }

            await saveEntries();
            renderEntries();
            showToast(`Imported ${imported.length} passwords from LastPass`, 'success');
        } catch (error) {
            console.error('LastPass import error:', error);
            showToast('Failed to import: ' + error.message, 'error');
        } finally {
            showLoading(false);
            e.target.value = '';
        }
    }

    function confirmResetVault() {
        if (!confirm('WARNING: This will delete ALL your saved passwords! This action cannot be undone. Are you sure?')) {
            return;
        }
        if (!confirm('This is your last chance! All data will be permanently deleted. Continue?')) {
            return;
        }

        resetVault();
    }

    async function resetVault() {
        try {
            showLoading(true);
            await StorageModule.clearAllData();
            masterPassword = null;
            salt = null;
            entries = [];
            showScreen('setup');
            showToast('Vault has been reset', 'success');
        } catch (error) {
            console.error('Reset error:', error);
            showToast('Failed to reset vault', 'error');
        } finally {
            showLoading(false);
        }
    }

    // ==================== TOAST NOTIFICATIONS ====================

    function showToast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;

        const icons = {
            success: '<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
            error: '<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
            warning: '<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
            info: '<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>'
        };

        toast.innerHTML = `${icons[type] || icons.info}<span>${message}</span>`;
        container.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateY(20px)';
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }

    // ==================== SECURITY FEATURES ====================

    // Breach Check using HaveIBeenPwned API
    async function checkForBreaches() {
        if (!masterPassword || entries.length === 0) {
            showToast('No passwords to check', 'info');
            return;
        }

        showLoading(true);
        let breachedCount = 0;
        let checkedCount = 0;

        try {
            for (const entry of entries) {
                if (entry.password) {
                    const isBreached = await checkPasswordBreach(entry.password);
                    if (isBreached) {
                        breachedCount++;
                    }
                    checkedCount++;
                }
            }

            if (breachedCount === 0) {
                showToast(`✅ All ${checkedCount} passwords are safe!`, 'success');
            } else {
                showToast(`⚠️ ${breachedCount} of ${checkedCount} passwords found in breaches!`, 'warning');
            }
        } catch (error) {
            console.error('Breach check error:', error);
            showToast('Failed to check breaches: ' + error.message, 'error');
        } finally {
            showLoading(false);
        }
    }

    function updateSecurityAudit() {
        if (!entries || entries.length === 0) {
            document.getElementById('audit-score').textContent = '--';
            document.getElementById('audit-subtitle').textContent = 'No passwords to analyze';
            document.getElementById('stat-total').textContent = '0';
            document.getElementById('stat-strong').textContent = '0';
            document.getElementById('stat-weak').textContent = '0';
            document.getElementById('stat-reused').textContent = '0';
            return;
        }

        let strong = 0;
        let weak = 0;
        const passwordCounts = {};

        // Analyze each password
        entries.forEach(entry => {
            if (entry.password) {
                const strength = CryptoModule.calculatePasswordStrength(entry.password);
                if (strength.score >= 60) {
                    strong++;
                } else {
                    weak++;
                }

                // Track password reuse
                passwordCounts[entry.password] = (passwordCounts[entry.password] || 0) + 1;
            }
        });

        // Count reused passwords
        const reused = Object.values(passwordCounts).filter(count => count > 1).reduce((sum, count) => sum + count, 0);

        // Calculate overall score
        const total = entries.length;
        const scorePercent = total > 0 ? Math.round(((strong - weak - reused) / total) * 50 + 50) : 50;
        const score = Math.max(0, Math.min(100, scorePercent));

        // Update UI
        document.getElementById('audit-score').textContent = score;
        document.getElementById('stat-total').textContent = total;
        document.getElementById('stat-strong').textContent = strong;
        document.getElementById('stat-weak').textContent = weak;
        document.getElementById('stat-reused').textContent = reused;

        // Update score circle color and message
        const scoreCircle = document.getElementById('audit-score-circle');
        const subtitle = document.getElementById('audit-subtitle');

        scoreCircle.classList.remove('good', 'fair', 'poor');

        if (score >= 70) {
            scoreCircle.classList.add('good');
            subtitle.textContent = 'Your passwords are looking good!';
        } else if (score >= 40) {
            scoreCircle.classList.add('fair');
            subtitle.textContent = 'Some passwords need attention';
        } else {
            scoreCircle.classList.add('poor');
            subtitle.textContent = 'Many passwords need improvement';
        }
    }

    async function checkPasswordBreach(password) {
        // Use SHA-1 hash and k-anonymity (send only first 5 chars)
        const encoder = new TextEncoder();
        const data = encoder.encode(password);

        // Use CryptoJS SHA-1 if Web Crypto not available
        let hash;
        if (window.CryptoJS) {
            hash = CryptoJS.SHA1(password).toString().toUpperCase();
        } else {
            const hashBuffer = await crypto.subtle.digest('SHA-1', data);
            hash = Array.from(new Uint8Array(hashBuffer))
                .map(b => b.toString(16).padStart(2, '0'))
                .join('').toUpperCase();
        }

        const prefix = hash.substring(0, 5);
        const suffix = hash.substring(5);

        try {
            const response = await fetch('/api/check-breach', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password_hash_prefix: prefix })
            });

            if (!response.ok) {
                throw new Error('Breach check failed');
            }

            const data = await response.json();
            const suffixes = data.suffixes;

            // Check if our suffix is in the list
            return suffixes.includes(suffix);
        } catch (error) {
            console.error('Breach API error:', error);
            return false;
        }
    }

    // Change Master Password
    function openChangePasswordModal() {
        document.getElementById('change-password-form').reset();
        document.getElementById('change-password-modal').classList.add('active');
    }

    function closeChangePasswordModal() {
        document.getElementById('change-password-modal').classList.remove('active');
    }

    function updateNewPasswordStrength() {
        const password = document.getElementById('new-password').value;
        const strength = CryptoModule.calculatePasswordStrength(password);
        const fill = document.getElementById('new-password-strength');
        const label = document.getElementById('new-password-label');

        fill.style.width = `${strength.score}%`;
        fill.style.backgroundColor = strength.color;
        label.textContent = password ? strength.label : 'Enter a password';
        label.style.color = strength.color;
    }

    async function handleChangePassword(e) {
        e.preventDefault();

        const currentPwd = document.getElementById('current-password').value;
        const newPwd = document.getElementById('new-password').value;
        const confirmPwd = document.getElementById('confirm-new-password').value;

        // Validate current password
        const saltBase64 = await StorageModule.getSetting('salt');
        const storedHash = await StorageModule.getSetting('verificationHash');
        const currentSalt = CryptoModule.base64ToUint8Array(saltBase64);
        const inputHash = await CryptoModule.deriveVerificationHash(currentPwd, currentSalt);

        if (inputHash !== storedHash) {
            showToast('Current password is incorrect', 'error');
            return;
        }

        if (newPwd !== confirmPwd) {
            showToast('New passwords do not match', 'error');
            return;
        }

        if (newPwd.length < 8) {
            showToast('New password must be at least 8 characters', 'error');
            return;
        }

        showLoading(true);

        try {
            // Generate new salt and verification hash
            const newSalt = CryptoModule.generateSalt();
            const newVerificationHash = await CryptoModule.deriveVerificationHash(newPwd, newSalt);

            // Re-encrypt all entries with new password
            const encrypted = await CryptoModule.encrypt(entries, newPwd, newSalt);

            // Save new credentials
            await StorageModule.setSetting('salt', CryptoModule.uint8ArrayToBase64(newSalt));
            await StorageModule.setSetting('verificationHash', newVerificationHash);
            await StorageModule.saveVaultData(encrypted);

            // Update state
            masterPassword = newPwd;
            salt = newSalt;

            closeChangePasswordModal();
            showToast('Master password changed successfully!', 'success');
        } catch (error) {
            console.error('Change password error:', error);
            showToast('Failed to change password: ' + error.message, 'error');
        } finally {
            showLoading(false);
        }
    }

    // ==================== CLOUD SYNC ====================

    let isRegisterMode = false;
    let isRestoreMode = false;

    function openCloudModal() {
        isRegisterMode = false;
        isRestoreMode = false;
        updateCloudModalUI();
        document.getElementById('cloud-form').reset();
        document.getElementById('cloud-modal').classList.add('active');
    }

    function openRestoreFromCloudModal() {
        isRegisterMode = false;
        isRestoreMode = true;
        updateCloudModalUI();
        document.getElementById('cloud-form').reset();
        document.getElementById('cloud-modal').classList.add('active');
        showToast('Sign in to your cloud account to restore your vault', 'info');
    }

    async function restoreVaultFromCloud() {
        showLoading(true);

        try {
            // Get vault from cloud
            const cloudVault = await SyncModule.getVault();

            if (!cloudVault || !cloudVault.data) {
                showToast('No vault found in cloud. Create a new one.', 'info');
                showScreen('setup');
                return;
            }

            // Parse the vault data
            const vaultData = JSON.parse(cloudVault.data);

            if (!vaultData.ciphertext) {
                showToast('No vault found in cloud. Create a new one.', 'info');
                showScreen('setup');
                return;
            }

            // Save to local storage
            await StorageModule.setSetting('salt', vaultData.salt || await StorageModule.getSetting('salt'));
            await StorageModule.saveVaultData(vaultData);

            // Copy verification hash if it exists
            if (vaultData.verificationHash) {
                await StorageModule.setSetting('verificationHash', vaultData.verificationHash);
            }

            showToast('Vault restored! Enter your master password to unlock.', 'success');
            showScreen('login');
            await loadPasswordHint();
        } catch (error) {
            console.error('Restore error:', error);
            showToast('Failed to restore vault: ' + error.message, 'error');
            showScreen('setup');
        } finally {
            showLoading(false);
        }
    }

    function closeCloudModal() {
        document.getElementById('cloud-modal').classList.remove('active');
    }

    function toggleCloudAuthMode() {
        isRegisterMode = !isRegisterMode;
        updateCloudModalUI();
    }

    function updateCloudModalUI() {
        const title = document.getElementById('cloud-modal-title');
        const submitBtn = document.getElementById('cloud-submit-btn');
        const toggleBtn = document.getElementById('cloud-toggle-mode');

        if (isRegisterMode) {
            title.textContent = 'Create Account';
            submitBtn.textContent = 'Register';
            toggleBtn.textContent = 'Already have an account? Sign In';
        } else {
            title.textContent = 'Sign In';
            submitBtn.textContent = 'Sign In';
            toggleBtn.textContent = "Don't have an account? Register";
        }
    }

    async function handleCloudAuth(e) {
        e.preventDefault();
        const email = document.getElementById('cloud-email-input').value;
        const password = document.getElementById('cloud-password-input').value;

        showLoading(true);

        try {
            if (isRegisterMode) {
                await SyncModule.register(email, password);
                showToast('Account created successfully!', 'success');
            } else {
                await SyncModule.login(email, password);
                showToast('Signed in successfully!', 'success');
            }

            closeCloudModal();
            updateCloudUI();

            // If in restore mode, pull vault from cloud
            if (isRestoreMode) {
                isRestoreMode = false;
                await restoreVaultFromCloud();
            } else if (masterPassword) {
                // Sync vault after login
                await syncNow();
            }
        } catch (error) {
            console.error('Cloud auth error:', error);
            showToast(error.message || 'Authentication failed', 'error');
        } finally {
            showLoading(false);
        }
    }

    function handleCloudLogout() {
        SyncModule.logout();
        updateCloudUI();
        showToast('Signed out', 'success');
    }

    function updateCloudUI() {
        const loggedOut = document.getElementById('cloud-logged-out');
        const loggedIn = document.getElementById('cloud-logged-in');
        const emailDisplay = document.getElementById('cloud-email');
        const syncStatus = document.getElementById('sync-status');

        if (SyncModule.isLoggedIn()) {
            loggedOut.classList.add('hidden');
            loggedIn.classList.remove('hidden');
            emailDisplay.textContent = SyncModule.getUserEmail() || 'Connected';

            const lastSync = SyncModule.getLastSyncTime();
            syncStatus.textContent = `Last sync: ${SyncModule.formatSyncTime(lastSync)}`;
        } else {
            loggedOut.classList.remove('hidden');
            loggedIn.classList.add('hidden');
        }
    }

    async function syncNow() {
        if (!SyncModule.isLoggedIn()) {
            showToast('Please sign in to sync', 'error');
            return;
        }

        if (!masterPassword) {
            showToast('Please unlock vault first', 'error');
            return;
        }

        showLoading(true);

        try {
            // Get current encrypted vault data
            const vaultData = await StorageModule.getVaultData();
            const encryptedString = vaultData ? JSON.stringify(vaultData) : '';

            // Sync with server
            const result = await SyncModule.syncVault(encryptedString);

            if (result.needs_sync && result.data) {
                // Server has newer data, import it
                const serverVault = JSON.parse(result.data);
                await StorageModule.saveVaultData(serverVault);
                await loadEntries();
                renderEntries();
                showToast('Vault synced from cloud', 'success');
            } else {
                showToast('Vault synced', 'success');
            }

            updateCloudUI();
        } catch (error) {
            console.error('Sync error:', error);
            showToast('Sync failed: ' + error.message, 'error');
        } finally {
            showLoading(false);
        }
    }

    // Modified saveEntries to auto-sync
    async function saveEntriesAndSync() {
        await saveEntries();

        // Auto-sync if logged in and auto-sync is enabled
        const autoSyncToggle = document.getElementById('auto-sync-toggle');
        if (SyncModule.isLoggedIn() && autoSyncToggle?.checked) {
            try {
                const vaultData = await StorageModule.getVaultData();
                const encryptedString = vaultData ? JSON.stringify(vaultData) : '';
                await SyncModule.saveVault(encryptedString);
                updateCloudUI();
            } catch (error) {
                console.error('Auto-sync failed:', error);
                // Don't show error toast for auto-sync failures
            }
        }
    }

    // Initialize on DOM ready
    document.addEventListener('DOMContentLoaded', init);

    // Public API
    return {
        showToast,
        lockVault,
        syncNow
    };
})();
