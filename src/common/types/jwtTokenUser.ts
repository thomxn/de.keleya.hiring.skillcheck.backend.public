export interface JwtTokenUser {
  email?: string | null;
  id: number | null;
}

export const isJwtTokenUser = (candidate: unknown): candidate is JwtTokenUser => {
  const user = candidate as JwtTokenUser;
  return user.email !== undefined && user.id !== undefined;
};
