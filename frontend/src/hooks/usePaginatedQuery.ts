import { useCallback, useEffect, useState } from "react";
import { getErrorMessage } from "../api/apiError";
import type { PaginatedResponse } from "../types/phantom";

export interface CursorParams {
  cursor?: string | null;
}

export type PaginatedFetch<T, P extends CursorParams> = (
  params: P,
) => Promise<PaginatedResponse<T>>;

export interface PaginatedQueryResult<T> {
  items: T[];
  loading: boolean;
  error: string | null;
  fetchNext: () => Promise<void>;
  hasMore: boolean;
}

export const appendPage = <T>(items: T[], page: PaginatedResponse<T>): T[] => [
  ...items,
  ...page.items,
];

export const usePaginatedQuery = <T, P extends CursorParams>(
  fetchFn: PaginatedFetch<T, P>,
  params: Omit<P, "cursor">,
): PaginatedQueryResult<T> => {
  const [items, setItems] = useState<T[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const paramsKey = JSON.stringify(params);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError(null);
    void fetchFn({ ...params, cursor: null } as P)
      .then((page) => {
        if (!active) return;
        setItems(page.items);
        setNextCursor(page.next_cursor);
      })
      .catch((reason: unknown) => {
        if (active) setError(getErrorMessage(reason));
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [fetchFn, params, paramsKey]);

  const fetchNext = useCallback(async (): Promise<void> => {
    if (nextCursor === null || loading) return;
    setLoading(true);
    setError(null);
    try {
      const page = await fetchFn({ ...params, cursor: nextCursor } as P);
      setItems((current) => appendPage(current, page));
      setNextCursor(page.next_cursor);
    } catch (reason: unknown) {
      setError(getErrorMessage(reason));
    } finally {
      setLoading(false);
    }
  }, [fetchFn, loading, nextCursor, params]);

  return { items, loading, error, fetchNext, hasMore: nextCursor !== null };
};
