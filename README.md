# Keycloak API Node

A NestJS-based package for Keycloak authentication and admin API integration.

## Features

- Token validation and role checking
- Admin token generation
- Keycloak admin API integration
- Custom decorators for easy role checking

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
  redirectUri: "http://localhost:3000/callback"
});
```

For NestJS applications, you can provide the service in your module:

```typescript
import { Module } from '@nestjs/common';
import { KeycloakService } from 'keycloak-api-node';

@Module({
  providers: [
    {
      provide: KeycloakService,
      useValue: new KeycloakService({
        clientId: "your-client-id",
        clientSecret: "your-client-secret",
        issuer: "https://your-keycloak-server/realms/your-realm",
        redirectUri: "http://localhost:3000/callback"
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
    return this.keycloakService.validateToken(token);
  }

  async addRole(roleName: string) {
    await this.keycloakService.addRole(roleName);
  }

  async getUserRoles(userId: string) {
    return this.keycloakService.getUserRoles(userId);
  }
}
```

## License

MIT
