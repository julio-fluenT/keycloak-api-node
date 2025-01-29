# Keycloak API Node

A NestJS-based package for Keycloak authentication and admin API integration.

## Features

- Token validation and role checking
- Admin token generation
- Keycloak admin API integration
- Custom decorators for easy role checking
- Secure token encryption and decryption

## Installation

```bash
npm install keycloak-api-node
```

## Configuration

You can initialize the KeycloakService with your configuration:

```typescript
import { KeycloakService } from 'keycloak-api-node';

const keycloakService = new KeycloakService({
  clientId: "your-client-id",
  clientSecret: "your-client-secret",
  issuer: "https://your-keycloak-server/realms/your-realm",
  redirectUri: "http://localhost:3000/callback",
  // Optional encryption configuration
  encryptionKey: "your-32-character-encryption-key", // Must be 32 characters
  iv: "your-16-character-iv"                         // Must be 16 characters
});
```

### Encryption Configuration

The service includes built-in AES-256-CBC encryption for enhanced security. You can configure it in two ways:

1. **Using Environment Variables (Recommended)**
   ```env
   KEYCLOAK_ENCRYPTION_KEY=your-32-character-encryption-key
   KEYCLOAK_IV=your-16-character-iv
   ```

2. **Direct Configuration**
   ```typescript
   const keycloakService = new KeycloakService({
     // ... other config
     encryptionKey: process.env.KEYCLOAK_ENCRYPTION_KEY,
     iv: process.env.KEYCLOAK_IV
   });
   ```

**Important Security Notes:**
- The encryption key must be exactly 32 characters long
- The initialization vector (IV) must be exactly 16 characters long
- Never commit encryption keys or IVs to version control
- Use environment variables in production
- If not provided, default values will be used (not recommended for production)

For NestJS applications, you can provide the service in your module:

```typescript
import { Module } from '@nestjs/common';
import { KeycloakService } from 'keycloak-api-node';

@Module({
  providers: [
    {
      provide: KeycloakService,
      useValue: new KeycloakService({
        clientId: process.env.KEYCLOAK_CLIENT_ID,
        clientSecret: process.env.KEYCLOAK_CLIENT_SECRET,
        issuer: process.env.KEYCLOAK_ISSUER,
        redirectUri: process.env.KEYCLOAK_REDIRECT_URI,
        encryptionKey: process.env.KEYCLOAK_ENCRYPTION_KEY,
        iv: process.env.KEYCLOAK_IV
      })
    }
  ],
  exports: [KeycloakService]
})
export class KeycloakModule {}
```

## Usage

### Module Setup

```typescript
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { KeycloakModule } from 'keycloak-api-node';

@Module({
  imports: [
    ConfigModule.forRoot(),
    KeycloakModule
  ],
})
export class AppModule {}
```

### Token Validation

You can use the `@ValidateToken()` decorator to automatically validate tokens in your controllers:

```typescript
import { Controller, Get } from '@nestjs/common';
import { ValidateToken } from 'keycloak-api-node';

@Controller('users')
export class UserController {
  @Get('profile')
  async getProfile(@ValidateToken() token: string) {
    // token is already validated and decrypted
    return this.userService.getProfile(token);
  }
}
```

The ValidateToken decorator will:
- Extract the token from the Authorization header
- Validate the token's format
- Decrypt the token if necessary
- Check token expiration
- Throw UnauthorizedException if validation fails

### Important Notes About Token Encryption

The package uses a shared EncryptionStore to maintain consistent encryption settings across your application. This means:

1. Encryption settings are shared application-wide
2. The last configuration set will be used for all token validations
3. If you're running multiple applications, they should use the same encryption settings

For production environments, always:
1. Set custom encryption keys through environment variables
2. Use different keys for different environments
3. Never use the default development keys

### Role-Based Access Control

Use the `@KeycloakRole()` decorator to protect routes:

```typescript
@Get('admin/users')
@KeycloakRole('admin')
async getUsers(@ValidateToken() token: string) {
  return this.userService.getAllUsers(token);
}
```

### Using the Decorator

```typescript
import { Controller, Get } from '@nestjs/common';
import { KeycloakRole } from 'keycloak-api-node';

@Controller('api')
export class AppController {
  @Get('protected')
  async protectedEndpoint(@KeycloakRole('admin') tokenData: any) {
    return 'This endpoint is protected and requires admin role';
  }
}
```

### Using the Service

```typescript
import { Injectable } from '@nestjs/common';
import { KeycloakService } from 'keycloak-api-node';

@Injectable()
export class YourService {
  constructor(private readonly keycloakService: KeycloakService) {}

  async validateToken(token: string) {
    // Token will be automatically decrypted before validation
    return this.keycloakService.validateToken(token);
  }

  async checkRole(token: string, role: string) {
    // Token will be automatically decrypted before role check
    return this.keycloakService.checkUserRole(token, role);
  }
}
```

## Security

This package implements several security measures:

1. **Token Encryption**: All tokens are encrypted using AES-256-CBC encryption
2. **Automatic Token Validation**: Includes expiration checking
3. **Role-based Access Control**: Built-in role checking functionality
4. **Secure Configuration**: Support for environment variables

## License

MIT
