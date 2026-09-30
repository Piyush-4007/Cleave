"""API Gateway collector — REST (v1) and HTTP (v2) APIs, and which routes need no auth.

A route with authorizationType NONE is invokable by anyone on the internet: an external
entry point, like an unauthenticated Lambda URL. Regional. Reads only.

Tracing what each route's integration then invokes (which Lambda, as which role) is a
deeper analysis not done here — this collector reports the entry point itself.
"""
from __future__ import annotations
from .base import collector, paginate


@collector("apigateway")
def collect(ctx) -> list[dict]:
    def in_region(region: str) -> list[dict]:
        out: list[dict] = []
        # ---- REST APIs (v1) ----
        try:
            rest = ctx.client("apigateway", region)
            for api in paginate(rest, "get_rest_apis", "items"):
                api_id = api["id"]
                public: list[str] = []
                try:
                    for res in paginate(rest, "get_resources", "items", restApiId=api_id):
                        path = res.get("path", "")
                        for method, cfg in (res.get("resourceMethods") or {}).items():
                            if method == "OPTIONS":
                                continue
                            # get_resources omits authorizationType; one get_method per method.
                            try:
                                m = rest.get_method(restApiId=api_id, resourceId=res["id"],
                                                    httpMethod=method)
                            except Exception:  # noqa: BLE001
                                continue
                            if m.get("authorizationType") in (None, "NONE") and not m.get("apiKeyRequired"):
                                public.append(f"{method} {path}")
                except Exception:  # noqa: BLE001 - keep the API even if routes are unreadable
                    pass
                out.append({
                    "_type": "ApiGatewayApi", "_id": f"arn:aws:apigateway:{region}::/restapis/{api_id}",
                    "Region": region, "Name": api.get("name"), "ApiId": api_id,
                    "Protocol": "REST", "PublicRoutes": sorted(public),
                })
        except Exception:  # noqa: BLE001
            pass
        # ---- HTTP / WebSocket APIs (v2) — authorizationType is on the route directly ----
        try:
            v2 = ctx.client("apigatewayv2", region)
            for api in paginate(v2, "get_apis", "Items"):
                api_id = api["ApiId"]
                public = []
                try:
                    for r in paginate(v2, "get_routes", "Items", ApiId=api_id):
                        if r.get("AuthorizationType") in (None, "NONE"):
                            public.append(r.get("RouteKey", "?"))
                except Exception:  # noqa: BLE001
                    pass
                out.append({
                    "_type": "ApiGatewayApi", "_id": api.get("ApiEndpoint") or f"{region}/{api_id}",
                    "Region": region, "Name": api.get("Name"), "ApiId": api_id,
                    "Protocol": api.get("ProtocolType", "HTTP"), "PublicRoutes": sorted(public),
                })
        except Exception:  # noqa: BLE001
            pass
        return out
    return ctx.per_region(in_region)
