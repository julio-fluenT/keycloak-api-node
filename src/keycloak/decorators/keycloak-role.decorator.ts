import {
  createParamDecorator,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { KeycloakService } from '../keycloak.service';

export const KeycloakRole = (requiredRole: string) => {
  return createParamDecorator(async (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    const token = request.headers.authorization?.split(' ')[1];

    if (!token) {
      throw new UnauthorizedException('No token provided');
    }

    const keycloakService = new KeycloakService(request.configService);
    const hasRole = await keycloakService.checkUserRole(token, requiredRole);

    if (!hasRole) {
      throw new UnauthorizedException(`Required role: ${requiredRole}`);
    }

    return await keycloakService.validateToken(token);
  });
};
