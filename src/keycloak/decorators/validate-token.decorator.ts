import {
  createParamDecorator,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { getDecodedAccessToken } from '../../utils/tokenUtils';
import { decrypt } from '../../utils/encryption';
import { EncryptionStore } from '../config/encryption.store';

export const ValidateToken = createParamDecorator(
  async (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    const authHeader = request.headers.authorization;

    if (!authHeader) {
      throw new UnauthorizedException('No authorization header found');
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
      throw new UnauthorizedException('No token provided');
    }

    try {
      // Get current encryption config from store
      const encryptionConfig = EncryptionStore.getInstance().getConfig();

      // Check if the token needs decryption
      const decryptedToken = token.startsWith('eyJh')
        ? token
        : decrypt(token, encryptionConfig);

      const decoded: any = getDecodedAccessToken(decryptedToken);
      if (!decoded) {
        throw new UnauthorizedException('Invalid token');
      }

      // Check token expiration
      const currentTime = Math.floor(Date.now() / 1000);
      if (decoded['exp'] && decoded['exp'] < currentTime) {
        throw new UnauthorizedException('Token expired');
      }

      return decryptedToken;
    } catch (error) {
      console.error('Token validation error:', error);
      throw new UnauthorizedException('Invalid token');
    }
  },
);
