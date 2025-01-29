import { Injectable, UnauthorizedException } from '@nestjs/common';
import axios from 'axios';
import { encrypt, decrypt } from '../utils/encryption';
import { getDecodedAccessToken } from '../utils/tokenUtils';

interface KeycloakConfig {
  clientId: string;
  clientSecret: string;
  issuer: string;
  redirectUri: string;
  encryptionKey?: string;
  iv?: string;
}

const DEFAULT_ENCRYPTION_KEY = 'f47ac10b58cc4372a5670e02b2c3d479';
const DEFAULT_IV = '1e72d836a2f1d4b8';

@Injectable()
export class KeycloakService {
  private readonly keycloakUrl: string;
  private readonly realm: string;
  private readonly clientId: string;
  private readonly clientSecret: string;
  private readonly redirectUri: string;
  private readonly encryptionConfig: { encryptionKey: string; iv: string };

  constructor(private config: KeycloakConfig) {
    const issuerUrl = new URL(config.issuer);
    this.keycloakUrl = `${issuerUrl.protocol}//${issuerUrl.host}`;
    this.realm = issuerUrl.pathname.split('/').pop() || '';
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this.redirectUri = config.redirectUri;
    this.encryptionConfig = {
      encryptionKey: config.encryptionKey || DEFAULT_ENCRYPTION_KEY,
      iv: config.iv || DEFAULT_IV,
    };
  }

  private decryptToken(encryptedToken: string): string {
    try {
      console.log('Encryption config lengths:', {
        keyLength: this.encryptionConfig.encryptionKey.length,
        ivLength: this.encryptionConfig.iv.length,
      });

      return decrypt(encryptedToken, this.encryptionConfig);
    } catch (error) {
      console.error('Token decryption failed:', {
        error: error.message,
        tokenLength: encryptedToken?.length,
      });
      throw error;
    }
  }

  async validateToken(token: string): Promise<any> {
    try {
      // Check if the token needs decryption
      const decryptedToken = token.startsWith('eyJh')
        ? token
        : this.decryptToken(token);

      const decoded: any = getDecodedAccessToken(decryptedToken);
      if (!decoded) {
        throw new UnauthorizedException('Invalid token');
      }

      // Check token expiration
      const currentTime = Math.floor(Date.now() / 1000);
      if (decoded['exp'] && decoded['exp'] < currentTime) {
        throw new UnauthorizedException('Token expired');
      }

      return decoded;
    } catch (error) {
      console.error('Token validation error:', error);
      throw new UnauthorizedException('Invalid token');
    }
  }

  async checkUserRole(token: string, requiredRole: string): Promise<boolean> {
    const decoded = await this.validateToken(token);
    const userRoles = decoded.realm_access?.roles || [];
    return userRoles.includes(requiredRole);
  }

  async generateAdminToken(): Promise<string> {
    try {
      const response = await axios.post(
        `${this.keycloakUrl}/realms/${this.realm}/protocol/openid-connect/token`,
        new URLSearchParams({
          grant_type: 'client_credentials',
          client_id: this.clientId,
          client_secret: this.clientSecret,
        }),
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        },
      );

      return response.data.access_token;
    } catch (error) {
      console.error('Failed to generate admin token:', error);
      throw new Error('Failed to generate admin token');
    }
  }

  private encryptToken(token: string): string {
    return encrypt(token, this.encryptionConfig);
  }

  async addRole(roleName: string, description?: string): Promise<void> {
    const token = await this.generateAdminToken();

    try {
      await axios.post(
        `${this.keycloakUrl}/admin/realms/${this.realm}/roles`,
        {
          name: roleName,
          description: description || `Role ${roleName}`,
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        },
      );
    } catch (error) {
      throw new Error(`Failed to add role: ${error.message}`);
    }
  }

  async getUserRoles(userId: string): Promise<string[]> {
    const token = await this.generateAdminToken();

    try {
      const response = await axios.get(
        `${this.keycloakUrl}/admin/realms/${this.realm}/users/${userId}/role-mappings`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        },
      );

      return response.data.map((role: any) => role.name);
    } catch (error) {
      throw new Error(`Failed to get user roles: ${error.message}`);
    }
  }
}
