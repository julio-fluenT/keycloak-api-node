import { ENCRYPTION_CONFIG } from './encryption.config';

export class EncryptionStore {
  private static instance: EncryptionStore;
  private encryptionKey: string = ENCRYPTION_CONFIG.DEFAULT_ENCRYPTION_KEY;
  private iv: string = ENCRYPTION_CONFIG.DEFAULT_IV;

  private constructor() {}

  static getInstance(): EncryptionStore {
    if (!EncryptionStore.instance) {
      EncryptionStore.instance = new EncryptionStore();
    }
    return EncryptionStore.instance;
  }

  setConfig(config: { encryptionKey?: string; iv?: string }) {
    if (config.encryptionKey) {
      this.encryptionKey = config.encryptionKey;
    }
    if (config.iv) {
      this.iv = config.iv;
    }
  }

  getConfig() {
    return {
      encryptionKey: this.encryptionKey,
      iv: this.iv,
    };
  }
}
