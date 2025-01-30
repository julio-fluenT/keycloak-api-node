import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
  createParamDecorator,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { getDecodedAccessToken } from '../../utils/tokenUtils';
import { decrypt } from '../../utils/encryption';
import { EncryptionStore } from '../config/encryption.store';

// Shared token validation logic
function validateToken(request: any) {
  const authHeader = request.headers.authorization;

  if (!authHeader) {
    throw new UnauthorizedException('No authorization header found');
  }

  const token = authHeader.split(' ')[1];
  if (!token) {
    throw new UnauthorizedException('No token provided');
  }

  try {
    const encryptionConfig = EncryptionStore.getInstance().getConfig();
    const decryptedToken = token.startsWith('eyJh')
      ? token
      : decrypt(token, encryptionConfig);
    const decoded: any = getDecodedAccessToken(decryptedToken);

    if (!decoded) {
      throw new UnauthorizedException('Invalid token');
    }

    const currentTime = Math.floor(Date.now() / 1000);
    if (decoded['exp'] && decoded['exp'] < currentTime) {
      throw new UnauthorizedException('Token expired');
    }

    // Attach decoded token to request
    request.user = decoded;
    return decoded;
  } catch (error) {
    console.error('Token validation error:', error);
    throw new UnauthorizedException('Invalid token');
  }
}

@Injectable()
export class ValidateTokenGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    validateToken(request);
    return true;
  }
}

export const ValidateToken = createParamDecorator(
  async (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    return validateToken(request);
  },
);
