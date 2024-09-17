from typing import Any

from pydenticore.security.claims.claims import ClaimsPrincipal, ClaimsIdentity, Claim

__all__ = (
    "principal_serialize",
    "principal_deserialize",
)


def _generate_identity_name(identity: ClaimsIdentity) -> str:
    is_default_name_claim_type = identity.name_claim_type == ClaimsIdentity.DEFAULT_NAME_CLAIM_TYPE
    is_default_role_claim_type = identity.role_claim_type == ClaimsIdentity.DEFAULT_ROLE_CLAIM_TYPE

    return "{auth}.{name}.{role}".format(
        auth=identity.authentication_type,
        name="None" if is_default_name_claim_type else identity.name_claim_type,
        role="None" if is_default_role_claim_type else identity.role_claim_type,
    )


def _parse_identity_name(key: str) -> tuple[str, str | None, str | None]:
    auth, name_type, role_type = key.rsplit(".", maxsplit=2)
    return auth, name_type if name_type != "None" else None, role_type if role_type != "None" else None


def principal_serialize(principal: ClaimsPrincipal) -> dict[str, Any] | None:
    if principal is None:
        return None

    result: dict[str, list[tuple[str, Any]]] = {}

    for identity in principal.identities:
        key = _generate_identity_name(identity)

        if key not in result:
            result[key] = []

        for claim in identity.claims:
            result[key].append((claim.type, claim.value,))

    return result


def principal_deserialize(data: dict) -> ClaimsPrincipal | None:
    if data is None:
        return None

    principal = ClaimsPrincipal()

    for key in data.keys():
        authentication_type, name_claim_type, role_claim_type = _parse_identity_name(key)
        identity = ClaimsIdentity(
            authentication_type,
            *[Claim(*claim_tuple) for claim_tuple in data[key]],
            name_claim_type=name_claim_type,
            role_claim_type=role_claim_type
        )
        principal.add_identities(identity)

    return principal
