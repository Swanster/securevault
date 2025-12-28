/**
 * SecureVault Encryption Module
 * Uses AES-256-GCM with PBKDF2 key derivation
 * Falls back to CryptoJS when Web Crypto API is not available (HTTP)
 */

const CryptoModule = (() => {
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();

    // PBKDF2 iterations - higher = more secure but slower
    const PBKDF2_ITERATIONS = 100000;
    const SALT_LENGTH = 16;
    const IV_LENGTH = 12;

    // Check if Web Crypto API is available
    const hasWebCrypto = !!(window.crypto && window.crypto.subtle);

    /**
     * Generate a random salt for key derivation
     */
    function generateSalt() {
        return crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
    }

    /**
     * Generate a random IV for encryption
     */
    function generateIV() {
        return crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    }

    // ==================== WEB CRYPTO IMPLEMENTATION ====================

    /**
     * Derive an AES-256 key from master password using PBKDF2 (Web Crypto)
     */
    async function deriveKeyWebCrypto(password, salt) {
        const keyMaterial = await crypto.subtle.importKey(
            "raw",
            encoder.encode(password),
            "PBKDF2",
            false,
            ["deriveKey"]
        );

        return crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: PBKDF2_ITERATIONS,
                hash: "SHA-256"
            },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );
    }

    /**
     * Derive verification hash (Web Crypto)
     */
    async function deriveVerificationHashWebCrypto(password, salt) {
        const keyMaterial = await crypto.subtle.importKey(
            "raw",
            encoder.encode(password),
            "PBKDF2",
            false,
            ["deriveBits"]
        );

        const bits = await crypto.subtle.deriveBits(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: PBKDF2_ITERATIONS,
                hash: "SHA-256"
            },
            keyMaterial,
            256
        );

        return arrayBufferToBase64(bits);
    }

    /**
     * Encrypt data (Web Crypto)
     */
    async function encryptWebCrypto(data, password, salt) {
        const key = await deriveKeyWebCrypto(password, salt);
        const iv = generateIV();
        const plaintext = encoder.encode(JSON.stringify(data));

        const ciphertext = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            key,
            plaintext
        );

        return {
            iv: arrayBufferToBase64(iv),
            ciphertext: arrayBufferToBase64(ciphertext)
        };
    }

    /**
     * Decrypt data (Web Crypto)
     */
    async function decryptWebCrypto(ciphertextBase64, ivBase64, password, salt) {
        const key = await deriveKeyWebCrypto(password, salt);
        const iv = base64ToArrayBuffer(ivBase64);
        const ciphertext = base64ToArrayBuffer(ciphertextBase64);

        const plaintext = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            ciphertext
        );

        return JSON.parse(decoder.decode(plaintext));
    }

    // ==================== CRYPTOJS FALLBACK IMPLEMENTATION ====================

    /**
     * Derive key using CryptoJS PBKDF2
     */
    function deriveKeyCryptoJS(password, salt) {
        const saltWordArray = CryptoJS.lib.WordArray.create(salt);
        return CryptoJS.PBKDF2(password, saltWordArray, {
            keySize: 256 / 32,
            iterations: PBKDF2_ITERATIONS,
            hasher: CryptoJS.algo.SHA256
        });
    }

    /**
     * Derive verification hash (CryptoJS)
     */
    async function deriveVerificationHashCryptoJS(password, salt) {
        const key = deriveKeyCryptoJS(password, salt);
        return CryptoJS.enc.Base64.stringify(key);
    }

    /**
     * Encrypt data (CryptoJS) - using AES-CBC as GCM not well supported
     */
    async function encryptCryptoJS(data, password, salt) {
        const key = deriveKeyCryptoJS(password, salt);
        const iv = generateIV();
        const ivWordArray = CryptoJS.lib.WordArray.create(iv);
        const plaintext = JSON.stringify(data);

        const encrypted = CryptoJS.AES.encrypt(plaintext, key, {
            iv: ivWordArray,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7
        });

        return {
            iv: arrayBufferToBase64(iv),
            ciphertext: encrypted.ciphertext.toString(CryptoJS.enc.Base64)
        };
    }

    /**
     * Decrypt data (CryptoJS)
     */
    async function decryptCryptoJS(ciphertextBase64, ivBase64, password, salt) {
        const key = deriveKeyCryptoJS(password, salt);
        const iv = base64ToArrayBuffer(ivBase64);
        const ivWordArray = CryptoJS.lib.WordArray.create(new Uint8Array(iv));

        const cipherParams = CryptoJS.lib.CipherParams.create({
            ciphertext: CryptoJS.enc.Base64.parse(ciphertextBase64)
        });

        const decrypted = CryptoJS.AES.decrypt(cipherParams, key, {
            iv: ivWordArray,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7
        });

        return JSON.parse(decrypted.toString(CryptoJS.enc.Utf8));
    }

    // ==================== PUBLIC API (AUTO-SELECT IMPLEMENTATION) ====================

    async function deriveKey(password, salt) {
        if (hasWebCrypto) {
            return deriveKeyWebCrypto(password, salt);
        }
        return deriveKeyCryptoJS(password, salt);
    }

    async function deriveVerificationHash(password, salt) {
        if (hasWebCrypto) {
            return deriveVerificationHashWebCrypto(password, salt);
        }
        return deriveVerificationHashCryptoJS(password, salt);
    }

    async function encrypt(data, password, salt) {
        if (hasWebCrypto) {
            return encryptWebCrypto(data, password, salt);
        }
        return encryptCryptoJS(data, password, salt);
    }

    async function decrypt(ciphertextBase64, ivBase64, password, salt) {
        if (hasWebCrypto) {
            return decryptWebCrypto(ciphertextBase64, ivBase64, password, salt);
        }
        return decryptCryptoJS(ciphertextBase64, ivBase64, password, salt);
    }

    /**
     * Generate a secure random password
     */
    function generatePassword(length = 16, options = {}) {
        const {
            uppercase = true,
            lowercase = true,
            numbers = true,
            symbols = true
        } = options;

        let chars = '';
        if (uppercase) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        if (lowercase) chars += 'abcdefghijklmnopqrstuvwxyz';
        if (numbers) chars += '0123456789';
        if (symbols) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';

        if (chars.length === 0) {
            chars = 'abcdefghijklmnopqrstuvwxyz';
        }

        const array = new Uint32Array(length);
        crypto.getRandomValues(array);

        let password = '';
        for (let i = 0; i < length; i++) {
            password += chars[array[i] % chars.length];
        }

        return password;
    }

    /**
     * Calculate password strength (0-100)
     */
    function calculatePasswordStrength(password) {
        let score = 0;

        if (password.length >= 8) score += 20;
        if (password.length >= 12) score += 20;
        if (password.length >= 16) score += 10;
        if (/[a-z]/.test(password)) score += 10;
        if (/[A-Z]/.test(password)) score += 10;
        if (/[0-9]/.test(password)) score += 10;
        if (/[^a-zA-Z0-9]/.test(password)) score += 20;

        let label, color;
        if (score < 30) {
            label = 'Weak';
            color = '#ef4444';
        } else if (score < 60) {
            label = 'Fair';
            color = '#f59e0b';
        } else if (score < 80) {
            label = 'Good';
            color = '#10b981';
        } else {
            label = 'Strong';
            color = '#22c55e';
        }

        return { score, label, color };
    }

    // Utility: ArrayBuffer to Base64
    function arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    // Utility: Base64 to ArrayBuffer
    function base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    // Utility: Uint8Array to Base64
    function uint8ArrayToBase64(uint8Array) {
        return arrayBufferToBase64(uint8Array.buffer);
    }

    // Utility: Base64 to Uint8Array
    function base64ToUint8Array(base64) {
        return new Uint8Array(base64ToArrayBuffer(base64));
    }

    // Log which crypto implementation is being used
    console.log(`CryptoModule: Using ${hasWebCrypto ? 'Web Crypto API' : 'CryptoJS fallback'}`);

    // Public API
    return {
        generateSalt,
        generateIV,
        deriveKey,
        deriveVerificationHash,
        encrypt,
        decrypt,
        generatePassword,
        calculatePasswordStrength,
        arrayBufferToBase64,
        base64ToArrayBuffer,
        uint8ArrayToBase64,
        base64ToUint8Array,
        hasWebCrypto
    };
})();

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = CryptoModule;
}
