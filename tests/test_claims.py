from dataclasses import dataclass

import pytest

from pydentity.security.claims import ClaimTypes, ClaimsPrincipal, ClaimsIdentity, Claim


@dataclass
class _User:
    username: str = "username"
    email: str = "username@email.com"


@pytest.fixture
def get_principal(get_identity):
    return ClaimsPrincipal(get_identity)


@pytest.fixture
def get_identity(get_claims):
    return ClaimsIdentity(claims=get_claims, authentication_type="AppAuthentication")


@pytest.fixture
def get_claims():
    return [
        Claim(ClaimTypes.Name, _User.username),
        Claim(ClaimTypes.Email, _User.email),
    ]


@pytest.mark.parametrize("claim_type, result", {
    (ClaimTypes.Name, True,),
    (ClaimTypes.Email, True,),
    (ClaimTypes.SecurityStamp, False,),
    (ClaimTypes.Actor, False,),
    (lambda x: x.type == ClaimTypes.Name, True,),
    (lambda x: x.type == ClaimTypes.Email, True,),
    (lambda x: x.type == ClaimTypes.SecurityStamp, False,),
    (lambda x: x.type == ClaimTypes.Actor, False,)
})
def test_identity_find_all(get_identity, claim_type, result):
    assert (len([c for c in get_identity.find_all(claim_type)]) > 0) is result


@pytest.mark.parametrize("claim_type, result", {
    (ClaimTypes.Name, True,),
    (ClaimTypes.Email, True,),
    (ClaimTypes.SecurityStamp, False,),
    (ClaimTypes.Actor, False,),
    (lambda x: x.type == ClaimTypes.Name, True,),
    (lambda x: x.type == ClaimTypes.Email, True,),
    (lambda x: x.type == ClaimTypes.SecurityStamp, False,),
    (lambda x: x.type == ClaimTypes.Actor, False,)
})
def test_identity_find_first(get_identity, claim_type, result):
    assert bool(get_identity.find_first(claim_type)) is result


@pytest.mark.parametrize("claim_type, result", {
    (ClaimTypes.Name, True,),
    (ClaimTypes.Email, True,),
    (ClaimTypes.SecurityStamp, False,),
    (ClaimTypes.Actor, False,),
    (lambda x: x.type == ClaimTypes.Name, True,),
    (lambda x: x.type == ClaimTypes.Email, True,),
    (lambda x: x.type == ClaimTypes.SecurityStamp, False,),
    (lambda x: x.type == ClaimTypes.Actor, False,)
})
def test_identity_find_first_value(get_identity, claim_type, result):
    assert bool(get_identity.find_first_value(claim_type)) is result


@pytest.mark.parametrize("claim_type, claim_value, result", {
    (ClaimTypes.Name, _User.username, True,),
    (ClaimTypes.Name, "Undefined", False,),
    (ClaimTypes.Email, _User.email, True,),
    (ClaimTypes.Email, "Undefined", False,),
    (ClaimTypes.SecurityStamp, "SecurityStamp", False,)
})
def test_identity_has_claim(get_identity, claim_type, claim_value, result):
    assert get_identity.has_claim(claim_type, claim_value) is result


@pytest.mark.parametrize("predicate, result", {
    (lambda x: x.type == ClaimTypes.Name and x.value == _User.username, True,),
    (lambda x: x.type == ClaimTypes.Email and x.value == _User.email, True,),
    (lambda x: x.type == ClaimTypes.Name and x.value == "User.username", False,),
    (lambda x: x.type == ClaimTypes.Email and x.value == "User.email", False,),
    (lambda x: x.type == ClaimTypes.SecurityStamp and x.value == "SecurityStamp", False,),
    (lambda x: x.type == ClaimTypes.Actor and x.value == "Actor", False,)
})
def test_identity_has_claim_with_predicate(get_identity, predicate, result):
    assert get_identity.has_claim(predicate) is result


@pytest.mark.parametrize("claim_type, result", {
    (ClaimTypes.Name, True,),
    (ClaimTypes.Email, True,),
    (ClaimTypes.SecurityStamp, False,),
    (ClaimTypes.Actor, False,),
    (lambda x: x.type == ClaimTypes.Name, True,),
    (lambda x: x.type == ClaimTypes.Email, True,),
    (lambda x: x.type == ClaimTypes.SecurityStamp, False,),
    (lambda x: x.type == ClaimTypes.Actor, False,)
})
def test_principal_find_all(get_principal, claim_type, result):
    assert (len([c for c in get_principal.find_all(claim_type)]) > 0) is result


@pytest.mark.parametrize("claim_type, result", {
    (ClaimTypes.Name, True,),
    (ClaimTypes.Email, True,),
    (ClaimTypes.SecurityStamp, False,),
    (ClaimTypes.Actor, False,),
    (lambda x: x.type == ClaimTypes.Name, True,),
    (lambda x: x.type == ClaimTypes.Email, True,),
    (lambda x: x.type == ClaimTypes.SecurityStamp, False,),
    (lambda x: x.type == ClaimTypes.Actor, False,)
})
def test_principal_find_first(get_principal, claim_type, result):
    assert bool(get_principal.find_first(claim_type)) is result


@pytest.mark.parametrize("claim_type, result", {
    (ClaimTypes.Name, True,),
    (ClaimTypes.Email, True,),
    (ClaimTypes.SecurityStamp, False,),
    (ClaimTypes.Actor, False,),
    (lambda x: x.type == ClaimTypes.Name, True,),
    (lambda x: x.type == ClaimTypes.Email, True,),
    (lambda x: x.type == ClaimTypes.SecurityStamp, False,),
    (lambda x: x.type == ClaimTypes.Actor, False,)
})
def test_principal_find_first_value(get_principal, claim_type, result):
    assert bool(get_principal.find_first_value(claim_type)) is result


@pytest.mark.parametrize("claim_type, claim_value, result", {
    (ClaimTypes.Name, _User.username, True,),
    (ClaimTypes.Email, _User.email, True,),
    (ClaimTypes.Name, "Undefined", False,),
    (ClaimTypes.Email, "Undefined", False,),
    (ClaimTypes.SecurityStamp, "SecurityStamp", False,)
})
def test_principal_has_claim(get_principal, claim_type, claim_value, result):
    assert get_principal.has_claim(claim_type, claim_value) is result


@pytest.mark.parametrize("predicate, result", {
    (lambda x: x.type == ClaimTypes.Name and x.value == _User.username, True,),
    (lambda x: x.type == ClaimTypes.Email and x.value == _User.email, True,),
    (lambda x: x.type == ClaimTypes.Email and x.value == "User.email", False,),
    (lambda x: x.type == ClaimTypes.SecurityStamp and x.value == _User.username, False,),
    (lambda x: x.type == ClaimTypes.Actor and x.value == "Undefined", False,)
})
def test_principal_has_claim_with_predicate(get_principal, predicate, result):
    assert get_principal.has_claim(predicate) is result


@pytest.mark.parametrize("role_name, result", {
    ("admin", True,),
    ("user", True,),
    ("AdmiN", False,),
    ("manager", False,)
})
def test_principal_is_in_role(get_principal, role_name, result):
    assert get_principal.is_in_role(role_name) is result


@pytest.mark.parametrize("role_name, result", {
    (("admin", "user"), True,),
    (("manager", "user",), False,),
    (("admin", "superuser",), True,)
})
def test_principal_is_in_all_roles(get_principal, role_name, result):
    assert get_principal.is_in_all_roles(*role_name) is result


@pytest.mark.parametrize("role_name, result", {
    (("admin", "user"), True,),
    (("superuser", "user",), True,),
    (("admin", "Manager",), True,),
    (("Admin", "Manager",), False,)
})
def test_principal_is_in_any_roles(get_principal, role_name, result):
    assert get_principal.is_in_any_role(*role_name) is result


def test_principal_serialize_deserialize(get_principal):
    dump = get_principal.dump()
    from_list = ClaimsPrincipal.from_list(dump)
    for claim_1, claim_2 in zip(from_list.claims, get_principal.claims):
        assert claim_1.type == claim_2.type
        assert claim_1.value == claim_2.value
        assert claim_1.subject.authentication_type == claim_2.subject.authentication_type
