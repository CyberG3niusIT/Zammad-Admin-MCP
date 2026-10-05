from collections.abc import Mapping
from typing import Any


def project_sessions(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, Mapping) or not isinstance(value.get("sessions"), list):
        raise RuntimeError("Zammad did not return its active sessions")
    assets = value.get("assets") if isinstance(value.get("assets"), Mapping) else {}
    users = assets.get("User") if isinstance(assets.get("User"), Mapping) else {}
    result: list[dict[str, Any]] = []
    for session in value["sessions"]:
        if not isinstance(session, Mapping) or isinstance(session.get("id"), bool) or not isinstance(session.get("id"), int):
            raise RuntimeError("Zammad returned an invalid session record")
        data = session.get("data") if isinstance(session.get("data"), Mapping) else {}
        user_id = data.get("user_id")
        user = users.get(str(user_id)) if isinstance(user_id, int) else None
        identity = {}
        if isinstance(user, Mapping):
            identity = {
                key: user[key]
                for key in ("firstname", "lastname", "login")
                if isinstance(user.get(key), str)
            }
        geo = data.get("geo") if isinstance(data.get("geo"), Mapping) else {}
        result.append({
            "id": session["id"],
            "user_id": user_id if isinstance(user_id, int) and not isinstance(user_id, bool) else None,
            "user": identity,
            "browser": data.get("user_agent") if isinstance(data.get("user_agent"), str) else None,
            "remote_ip": data.get("remote_ip") if isinstance(data.get("remote_ip"), str) else None,
            "location": {
                key: geo[key]
                for key in ("country_name", "city_name")
                if isinstance(geo.get(key), str)
            },
            "persistent": session.get("persistent") if isinstance(session.get("persistent"), bool) else None,
            "created_at": session.get("created_at") if isinstance(session.get("created_at"), str) else None,
            "updated_at": session.get("updated_at") if isinstance(session.get("updated_at"), str) else None,
        })
    return result
