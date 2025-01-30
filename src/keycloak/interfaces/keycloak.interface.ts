export interface KeycloakConfig {
  clientId: string;
  clientSecret: string;
  issuer: string;
  redirectUri: string;
  encryptionKey?: string;
  iv?: string;
}

export interface KeycloakUser {
  firstName: string;
  lastName: string;
  email: string;
  password?: string;
  enabled?: boolean;
  roles?: string[];
}

export interface KeycloakRole {
  name: string;
  description?: string;
}

export interface KeycloakTokenResponse {
  access_token: string;
  expires_in: number;
  refresh_expires_in: number;
  token_type: string;
  scope: string;
}

export interface KeycloakError {
  error: string;
  error_description: string;
  status?: number;
}
