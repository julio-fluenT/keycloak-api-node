import { HttpException, HttpStatus } from '@nestjs/common';
import { KeycloakError } from '../interfaces/keycloak.interface';

export class KeycloakException extends HttpException {
  constructor(error: KeycloakError | string) {
    const errorMessage =
      typeof error === 'string'
        ? error
        : error.error_description || error.error;
    const statusCode =
      typeof error === 'string'
        ? HttpStatus.INTERNAL_SERVER_ERROR
        : error.status || HttpStatus.INTERNAL_SERVER_ERROR;

    super(
      {
        statusCode,
        message: errorMessage,
        error: typeof error === 'string' ? 'Keycloak Error' : error.error,
      },
      statusCode,
    );
  }
}
