import type { ErrorResponse } from "../types/phantom";

export class ApiError extends Error {
  public readonly status: number;
  public readonly errorCode: string;
  public readonly requestId: string | null;
  public readonly details: ErrorResponse["details"];

  public constructor(
    status: number,
    errorCode: string,
    message: string,
    requestId: string | null,
    details: ErrorResponse["details"] = {},
  ) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.errorCode = errorCode;
    this.requestId = requestId;
    this.details = details;
  }
}

export const getErrorMessage = (error: unknown): string =>
  error instanceof Error ? error.message : "An unexpected error occurred.";
