"""Lambda collector — functions, execution roles, function URLs, env vars. Regional."""
from __future__ import annotations
from .base import collector, paginate


@collector("lambda")
def collect(ctx) -> list[dict]:
    def in_region(region: str) -> list[dict]:
        out: list[dict] = []
        try:
            lam = ctx.client("lambda", region)
            for fn in paginate(lam, "list_functions", "Functions"):
                name = fn["FunctionName"]
                url_auth = None
                try:
                    url_auth = lam.get_function_url_config(FunctionName=name).get("AuthType")
                except Exception:  # noqa: BLE001 - no URL configured
                    pass
                out.append({
                    "_type": "LambdaFunction", "_id": fn["FunctionArn"], "Region": region,
                    "FunctionName": name, "Arn": fn["FunctionArn"],
                    "Role": fn.get("Role"), "Runtime": fn.get("Runtime"),
                    "FunctionUrlAuthType": url_auth,
                    "EnvVars": (fn.get("Environment") or {}).get("Variables", {}),
                })
        except Exception:  # noqa: BLE001
            pass  # keep what this region yielded before the failure
        return out

    return ctx.per_region(in_region)
