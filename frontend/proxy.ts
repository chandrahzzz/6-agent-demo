import { type NextRequest, NextResponse } from "next/server";

/** Send unauthenticated visitors to /login. The API still enforces auth on every request. */
export function proxy(req: NextRequest) {
  const hasSession = req.cookies.has("mallya_session");
  const { pathname } = req.nextUrl;
  if (!hasSession && pathname !== "/login") {
    const url = req.nextUrl.clone();
    url.pathname = "/login";
    url.search = pathname === "/" ? "" : `?next=${encodeURIComponent(pathname)}`;
    return NextResponse.redirect(url);
  }
  return NextResponse.next();
}

export const config = { matcher: ["/((?!api|_next|favicon.ico|.*\\.).*)"] };
