from typing import Any

from pydentity.security.claims import ClaimsPrincipal, ClaimsIdentity, Claim


class ClaimsPrincipalSerializer:
    @staticmethod
    def serialize(principal: ClaimsPrincipal) -> dict:
        if principal is None:
            raise ValueError

        result: dict[str, list[tuple[str, Any]]] = {}
        for identity in principal.identities:
            is_default_name = identity.name_claim_type == ClaimsIdentity.DEFAULT_NAME_CLAIM_TYPE
            is_default_role = identity.role_claim_type == ClaimsIdentity.DEFAULT_ROLE_CLAIM_TYPE
            key = f'{identity.authentication_type}'

            if not is_default_name:
                key += f'.{identity.name_claim_type}'
                if not is_default_role:
                    key += f'.{identity.role_claim_type}'
            elif not is_default_role:
                key += f'.None.{identity.role_claim_type}'

            if key not in result:
                result[key] = []

            for claim in identity.claims:
                result[key].append((claim.type, claim.value))

        return result

    @staticmethod
    def deserialize(data: dict) -> ClaimsPrincipal | None:
        if not data:
            raise ValueError

        principal = ClaimsPrincipal()
        for k in data.keys():
            key_chunks = k.split('.')
            match len(key_chunks):
                case 1:
                    identity = ClaimsIdentity(authentication_type=key_chunks[0])
                case 2:
                    identity = ClaimsIdentity(
                        authentication_type=key_chunks[0],
                        name_claim_type=key_chunks[1]
                    )
                case 3:
                    identity = ClaimsIdentity(
                        authentication_type=key_chunks[0],
                        name_claim_type=key_chunks[1],
                        role_claim_type=key_chunks[2]
                    )
                case _:
                    raise KeyError

            identity.add_claims(*[Claim(claim_tuple[0], claim_tuple[1]) for claim_tuple in data[k]])
            principal.add_identities(identity)
        return principal

