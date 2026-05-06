// =============================================================
// 🔍 jwtUtils — Utilidades para inspeccionar el JWT
// =============================================================
// - parseJwt(token): decodifica el payload del JWT (sin verificar firma)
// - getTokenMeta(token): devuelve info útil para la UI de seguridad:
//     * exp (Date)
//     * iat (Date)
//     * expiresInMs
//     * expired (boolean)
// =============================================================

export function parseJwt(token) {
  try {
    if (!token || typeof token !== "string") return null;
    const parts = token.split(".");
    if (parts.length !== 3) return null;

    const payload = parts[1];
    const decoded = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
    return JSON.parse(decoded);
  } catch (err) {
    console.warn("[jwtUtils] Error decodificando JWT:", err);
    return null;
  }
}

export function getTokenMeta(token) {
  const payload = parseJwt(token);
  if (!payload || (!payload.exp && !payload.iat)) {
    return {
      payload: payload || null,
      expDate: null,
      iatDate: null,
      expiresInMs: null,
      expired: null,
    };
  }

  const nowMs = Date.now();
  const expMs = payload.exp ? payload.exp * 1000 : null;
  const iatMs = payload.iat ? payload.iat * 1000 : null;

  const expiresInMs = expMs != null ? expMs - nowMs : null;
  const expired = expMs != null ? expiresInMs <= 0 : null;

  return {
    payload,
    expDate: expMs != null ? new Date(expMs) : null,
    iatDate: iatMs != null ? new Date(iatMs) : null,
    expiresInMs,
    expired,
  };
}