export const KEYCLOAK_ENDPOINTS = {
  TOKEN: '/protocol/openid-connect/token',
  USERS: '/admin/realms/{realm}/users',
  ROLES: '/admin/realms/{realm}/roles',
  USER_ROLES: '/admin/realms/{realm}/users/{userId}/role-mappings/realm',
} as const;

export const ERROR_MESSAGES = {
  INVALID_TOKEN: 'Invalid token',
  TOKEN_EXPIRED: 'Token expired',
  ADMIN_TOKEN_FAILED: 'Failed to generate admin token',
  USER_REGISTRATION_FAILED: 'Failed to register user',
  ROLE_CREATION_FAILED: 'Failed to create role',
  USER_ROLES_FETCH_FAILED: 'Failed to fetch user roles',
} as const;
