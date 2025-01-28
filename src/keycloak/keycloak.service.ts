import { Injectable, UnauthorizedException } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import axios from 'axios';
import { encrypt, decrypt } from '../utils/encryption';

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
  private adminToken: string;
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

  private encryptToken(token: string): string {
    return encrypt(token, this.encryptionConfig);
  }

  private decryptToken(encryptedToken: string): string {
    return decrypt(encryptedToken, this.encryptionConfig);
  }

  async validateToken(token: string): Promise<any> {
    try {
      const decryptedToken = this.decryptToken(token);
      const decoded: any = jwt.decode(decryptedToken);
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

      const token = response.data.access_token;
      this.adminToken = this.encryptToken(token);
      return this.adminToken;
    } catch (error) {
      console.error('Failed to generate admin token:', error);
      throw new Error('Failed to generate admin token');
    }
  }

  async addRole(roleName: string, description?: string): Promise<void> {
    const encryptedToken = await this.generateAdminToken();
    const token = this.decryptToken(encryptedToken);

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
    const encryptedToken = await this.generateAdminToken();
    const token = this.decryptToken(encryptedToken);

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
