import { Injectable, UnauthorizedException } from '@nestjs/common';
import axios from 'axios';
import { encrypt, decrypt } from '../utils/encryption';
import { getDecodedAccessToken } from '../utils/tokenUtils';
import { ENCRYPTION_CONFIG } from './config/encryption.config';
import { EncryptionStore } from './config/encryption.store';

interface KeycloakConfig {
  clientId: string;
  clientSecret: string;
  issuer: string;
  redirectUri: string;
  encryptionKey?: string;
  iv?: string;
}

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

    // Set up encryption config
    this.encryptionConfig = {
      encryptionKey:
        config.encryptionKey || ENCRYPTION_CONFIG.DEFAULT_ENCRYPTION_KEY,
      iv: config.iv || ENCRYPTION_CONFIG.DEFAULT_IV,
    };

    // Update the encryption store with the current config
    EncryptionStore.getInstance().setConfig(this.encryptionConfig);
  }

  private decryptToken(encryptedToken: string): string {
    try {
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

  async getUserRolesByEmail(email: string): Promise<{ roles: string[] }> {
    try {
      const token = await this.generateAdminToken();
      // Get user ID from email
      const usersResponse = await axios.get(
        `${this.keycloakUrl}/admin/realms/${this.realm}/users`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
          params: {
            email: email,
            exact: true,
          },
        },
      );

      const users = usersResponse.data;
      if (!users || users.length === 0) {
        return { roles: [] };
      }

      const userId = users[0].id;

      // Get user roles
      const rolesResponse = await axios.get(
        `${this.keycloakUrl}/admin/realms/${this.realm}/users/${userId}/role-mappings/realm`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        },
      );

      return {
        roles: rolesResponse.data.map((role: any) => role.name),
      };
    } catch (error) {
      console.error('Error getting user roles:', error);
      throw new UnauthorizedException('Failed to get user roles');
    }
  }
}
