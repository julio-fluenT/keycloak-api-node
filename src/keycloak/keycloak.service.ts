import { Injectable, Logger } from '@nestjs/common';
import axios from 'axios';
import { encrypt, decrypt } from '../utils/encryption';
import { getDecodedAccessToken } from '../utils/tokenUtils';
import { ENCRYPTION_CONFIG } from './config/encryption.config';
import { EncryptionStore } from './config/encryption.store';
import {
  KeycloakConfig,
  KeycloakUser,
  KeycloakRole,
  KeycloakTokenResponse,
} from './interfaces/keycloak.interface';
import { KeycloakException } from './exceptions/keycloak.exception';
import {
  KEYCLOAK_ENDPOINTS,
  ERROR_MESSAGES,
} from './constants/keycloak.constants';

@Injectable()
export class KeycloakService {
  private readonly logger = new Logger(KeycloakService.name);
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
      encryptionKey:
        config.encryptionKey || ENCRYPTION_CONFIG.DEFAULT_ENCRYPTION_KEY,
      iv: config.iv || ENCRYPTION_CONFIG.DEFAULT_IV,
    };

    EncryptionStore.getInstance().setConfig(this.encryptionConfig);
  }

  private encryptToken(token: string): string {
    try {
      return encrypt(token, this.encryptionConfig);
    } catch (error) {
      this.logger.error('Token encryption failed', error);
      throw new KeycloakException('Token encryption failed');
    }
  }

  private decryptToken(encryptedToken: string): string {
    try {
      return decrypt(encryptedToken, this.encryptionConfig);
    } catch (error) {
      this.logger.error('Token decryption failed', {
        error: error.message,
        tokenLength: encryptedToken?.length,
      });
      throw new KeycloakException('Token decryption failed');
    }
  }

  async validateToken(token: string): Promise<any> {
    try {
      const decryptedToken = token.startsWith('eyJh')
        ? token
        : this.decryptToken(token);

      const decoded = getDecodedAccessToken(decryptedToken);
      if (!decoded) {
        throw new KeycloakException(ERROR_MESSAGES.INVALID_TOKEN);
      }

      const currentTime = Math.floor(Date.now() / 1000);
      if (decoded['exp'] && decoded['exp'] < currentTime) {
        throw new KeycloakException(ERROR_MESSAGES.TOKEN_EXPIRED);
      }

      return decoded;
    } catch (error) {
      this.logger.error('Token validation error:', error);
      throw new KeycloakException(ERROR_MESSAGES.INVALID_TOKEN);
    }
  }

  async checkUserRole(token: string, requiredRole: string): Promise<boolean> {
    const decoded = await this.validateToken(token);
    const userRoles = decoded.realm_access?.roles || [];
    return userRoles.includes(requiredRole);
  }

  async generateAdminToken(): Promise<string> {
    try {
      const response = await axios.post<KeycloakTokenResponse>(
        `${this.keycloakUrl}/realms/${this.realm}${KEYCLOAK_ENDPOINTS.TOKEN}`,
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
      this.logger.error('Failed to generate admin token:', error);
      throw new KeycloakException(ERROR_MESSAGES.ADMIN_TOKEN_FAILED);
    }
  }

  async addRole(role: KeycloakRole): Promise<void> {
    const token = await this.generateAdminToken();

    try {
      await axios.post(
        `${this.keycloakUrl}/admin/realms/${this.realm}${KEYCLOAK_ENDPOINTS.ROLES}`,
        {
          name: role.name,
          description: role.description || `Role ${role.name}`,
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        },
      );
    } catch (error) {
      this.logger.error('Failed to add role:', error);
      throw new KeycloakException(ERROR_MESSAGES.ROLE_CREATION_FAILED);
    }
  }

  async getUserRoles(userId: string): Promise<string[]> {
    const token = await this.generateAdminToken();

    try {
      const response = await axios.get(
        `${this.keycloakUrl}${KEYCLOAK_ENDPOINTS.USER_ROLES.replace('{realm}', this.realm).replace('{userId}', userId)}`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        },
      );

      return response.data.map((role: any) => role.name);
    } catch (error) {
      this.logger.error('Failed to get user roles:', error);
      throw new KeycloakException(ERROR_MESSAGES.USER_ROLES_FETCH_FAILED);
    }
  }

  async getUserRolesByEmail(email: string): Promise<{ roles: string[] }> {
    try {
      const token = await this.generateAdminToken();
      const usersResponse = await axios.get(
        `${this.keycloakUrl}${KEYCLOAK_ENDPOINTS.USERS.replace('{realm}', this.realm)}`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
          params: {
            email,
            exact: true,
          },
        },
      );

      const users = usersResponse.data;
      if (!users || users.length === 0) {
        return { roles: [] };
      }

      const userId = users[0].id;
      const rolesResponse = await axios.get(
        `${this.keycloakUrl}${KEYCLOAK_ENDPOINTS.USER_ROLES.replace('{realm}', this.realm).replace('{userId}', userId)}`,
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
      this.logger.error('Error getting user roles:', error);
      throw new KeycloakException(ERROR_MESSAGES.USER_ROLES_FETCH_FAILED);
    }
  }

  async registerUser(user: KeycloakUser): Promise<boolean> {
    const token = await this.generateAdminToken();

    try {
      await axios.post(
        `${this.keycloakUrl}${KEYCLOAK_ENDPOINTS.USERS.replace('{realm}', this.realm)}`,
        {
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          enabled: user.enabled ?? true,
          username: user.email,
          credentials: user.password
            ? [
                {
                  type: 'password',
                  value: user.password,
                  temporary: false,
                },
              ]
            : undefined,
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        },
      );

      if (user.roles?.length) {
        const users = await axios.get(
          `${this.keycloakUrl}${KEYCLOAK_ENDPOINTS.USERS.replace('{realm}', this.realm)}`,
          {
            headers: { Authorization: `Bearer ${token}` },
            params: { email: user.email, exact: true },
          },
        );

        if (users.data?.[0]?.id) {
          const userId = users.data[0].id;
          await this.assignRolesToUser(userId, user.roles);
        }
      }

      return true;
    } catch (error) {
      this.logger.error('Failed to register user:', error);
      throw new KeycloakException(ERROR_MESSAGES.USER_REGISTRATION_FAILED);
    }
  }

  private async assignRolesToUser(
    userId: string,
    roles: string[],
  ): Promise<void> {
    const token = await this.generateAdminToken();

    try {
      const availableRoles = await axios.get(
        `${this.keycloakUrl}${KEYCLOAK_ENDPOINTS.ROLES.replace('{realm}', this.realm)}`,
        {
          headers: { Authorization: `Bearer ${token}` },
        },
      );

      const rolesToAssign = availableRoles.data
        .filter((role: any) => roles.includes(role.name))
        .map((role: any) => ({
          id: role.id,
          name: role.name,
        }));

      if (rolesToAssign.length) {
        await axios.post(
          `${this.keycloakUrl}${KEYCLOAK_ENDPOINTS.USER_ROLES.replace('{realm}', this.realm).replace('{userId}', userId)}`,
          rolesToAssign,
          {
            headers: {
              Authorization: `Bearer ${token}`,
              'Content-Type': 'application/json',
            },
          },
        );
      }
    } catch (error) {
      this.logger.error('Failed to assign roles to user:', error);
      throw new KeycloakException('Failed to assign roles to user');
    }
  }
}
