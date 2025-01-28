import { encrypt, decrypt } from './encryption';

describe('Encryption Utils', () => {
  const testEncryptionConfig = {
    encryptionKey: 'f47ac10b58cc4372a5670e02b2c3d479',
    iv: '1e72d836a2f1d4b8',
  };

  const testText = 'Hello, World!';

  it('should encrypt and decrypt text correctly', () => {
    const encrypted = encrypt(testText, testEncryptionConfig);
    const decrypted = decrypt(encrypted, testEncryptionConfig);
    expect(decrypted).toBe(testText);
  });

  it('should throw error if encryption key length is invalid', () => {
    const invalidConfig = {
      encryptionKey: 'short-key',
      iv: testEncryptionConfig.iv,
    };
    expect(() => encrypt(testText, invalidConfig)).toThrow('Encryption key must be 32 characters long');
  });

  it('should throw error if IV length is invalid', () => {
    const invalidConfig = {
      encryptionKey: testEncryptionConfig.encryptionKey,
      iv: 'short-iv',
    };
    expect(() => encrypt(testText, invalidConfig)).toThrow('Initialization vector (IV) must be 16 characters long');
  });

  it('should produce different encrypted values for same text with different keys', () => {
    const alternateConfig = {
      encryptionKey: 'a47ac10b58cc4372a5670e02b2c3d479',
      iv: '2e72d836a2f1d4b8',
    };

    const encrypted1 = encrypt(testText, testEncryptionConfig);
    const encrypted2 = encrypt(testText, alternateConfig);
    expect(encrypted1).not.toBe(encrypted2);
  });
});
