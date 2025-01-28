import crypto from 'crypto';

export function encrypt(
  text: string,
  encryptionConfig: { encryptionKey: string; iv: string },
): string {
  const { encryptionKey, iv } = encryptionConfig;
  if (encryptionKey.length !== 32) {
    throw new Error('Encryption key must be 32 characters long');
  }
  if (iv.length !== 16) {
    throw new Error('Initialization vector (IV) must be 16 characters long');
  }

  const cipher = crypto.createCipheriv(
    'aes-256-cbc',
    Buffer.from(encryptionKey),
    Buffer.from(iv),
  );
  let encrypted = cipher.update(text, 'utf-8', 'base64');
  encrypted += cipher.final('base64');
  return encrypted;
}

export function decrypt(
  encryptedString: string,
  encryptionConfig: { encryptionKey: string; iv: string },
): string {
  const { encryptionKey, iv } = encryptionConfig;
  if (encryptionKey.length !== 32) {
    throw new Error('Decryption key must be 32 characters long');
  }
  if (iv.length !== 16) {
    throw new Error('Initialization vector (IV) must be 16 characters long');
  }

  const decipher = crypto.createDecipheriv(
    'aes-256-cbc',
    Buffer.from(encryptionKey),
    Buffer.from(iv),
  );
  let decrypted = decipher.update(encryptedString, 'base64', 'utf-8');
  decrypted += decipher.final('utf-8');
  return decrypted;
}
