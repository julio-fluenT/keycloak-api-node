import { Injectable, UnauthorizedException } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import axios from 'axios';

interface KeycloakConfig {
  clientId: string;
  clientSecret: string;
  issuer: string;
  redirectUri: string;
}

@Injectable()
export class KeycloakService {
  private adminToken: string;
  private readonly keycloakUrl: string;
  private readonly realm: string;
  private readonly clientId: string;
  private readonly clientSecret: string;
  private readonly redirectUri: string;

  constructor(private config: KeycloakConfig) {
    const issuerUrl = new URL(config.issuer);
    this.keycloakUrl = `${issuerUrl.protocol}//${issuerUrl.host}`;
    this.realm = issuerUrl.pathname.split('/').pop() || '';
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this.redirectUri = config.redirectUri;
  }

  async validateToken(token: string): Promise<any> {
    try {
      const decoded: any = jwt.decode(token);
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

      this.adminToken = response.data.access_token;
      return this.adminToken;
    } catch (error) {
      console.error('Failed to generate admin token:', error);
      throw new Error('Failed to generate admin token');
    }
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
