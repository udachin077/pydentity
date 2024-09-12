import pytest

from pydenticore.security.claims import ClaimTypes, ClaimsPrincipal, ClaimsIdentity, Claim
from tests.conftest import User


@pytest.fixture
def principal(identity):
    return ClaimsPrincipal(identity)


@pytest.fixture
def identity(claims):
    return ClaimsIdentity("AppAuthentication", *claims)


@pytest.fixture
def claims():
    return [
        Claim(ClaimTypes.Name, User.username),
        Claim(ClaimTypes.Email, User.email),
        Claim(ClaimTypes.Role, 'admin'),
        Claim(ClaimTypes.Role, 'user')
    ]


@pytest.mark.parametrize("_match, result", {
    (ClaimTypes.Name, True,),
    (lambda x: x.type == ClaimTypes.Name, True,),
    (ClaimTypes.SecurityStamp, False,),
    (lambda x: x.type == ClaimTypes.SecurityStamp, False,),
})
def test_identity_find_all(_match, result, identity):
    assert (len([c for c in identity.find_all(_match)]) > 0) is result


@pytest.mark.parametrize("_match, result", {
    (ClaimTypes.Name, True,),
    (lambda x: x.type == ClaimTypes.Name, True,),
    (ClaimTypes.SecurityStamp, False,),
    (lambda x: x.type == ClaimTypes.SecurityStamp, False,),
})
def test_identity_find_first(_match, result, identity):
    assert bool(identity.find_first(_match)) is result


@pytest.mark.parametrize("_match, result", {
    (ClaimTypes.Name, True,),
    (lambda x: x.type == ClaimTypes.Name, True,),
    (ClaimTypes.SecurityStamp, False,),
    (lambda x: x.type == ClaimTypes.SecurityStamp, False,),
})
def test_identity_find_first_value(_match, result, identity):
    assert bool(identity.find_first_value(_match)) is result


@pytest.mark.parametrize("_match, result", {
    ((ClaimTypes.Name, User.username,), True,),
    ((ClaimTypes.Name, "Undefined",), False,),
    ((ClaimTypes.SecurityStamp, "SecurityStamp",), False,),
    ((lambda x: x.type == ClaimTypes.Name and x.value == User.username,), True,),
    ((lambda x: x.type == ClaimTypes.Name and x.value == "User.username",), False,),
    ((lambda x: x.type == ClaimTypes.SecurityStamp and x.value == "SecurityStamp",), False,),
})
def test_identity_has_claim(_match, result, identity):
    assert identity.has_claim(*_match) is result  # noqa


@pytest.mark.parametrize("claim_type, result", {
    (ClaimTypes.Name, True,),
    (lambda x: x.type == ClaimTypes.Name, True,),
    (ClaimTypes.SecurityStamp, False,),
    (lambda x: x.type == ClaimTypes.SecurityStamp, False,),
})
def test_principal_find_all(claim_type, result, principal):
    assert (len([c for c in principal.find_all(claim_type)]) > 0) is result


@pytest.mark.parametrize("claim_type, result", {
    (ClaimTypes.Name, True,),
    (lambda x: x.type == ClaimTypes.Name, True,),
    (ClaimTypes.SecurityStamp, False,),
    (lambda x: x.type == ClaimTypes.SecurityStamp, False,),
})
def test_principal_find_first(claim_type, result, principal):
    assert bool(principal.find_first(claim_type)) is result


@pytest.mark.parametrize("claim_type, result", {
    (ClaimTypes.Name, True,),
    (lambda x: x.type == ClaimTypes.Name, True,),
    (ClaimTypes.SecurityStamp, False,),
    (lambda x: x.type == ClaimTypes.SecurityStamp, False,),
})
def test_principal_find_first_value(claim_type, result, principal):
    assert bool(principal.find_first_value(claim_type)) is result


@pytest.mark.parametrize("_match, result", {
    ((ClaimTypes.Name, User.username,), True,),
    ((ClaimTypes.Name, "Undefined",), False,),
    ((ClaimTypes.SecurityStamp, "SecurityStamp",), False,),
    ((lambda x: x.type == ClaimTypes.Name and x.value == User.username,), True,),
    ((lambda x: x.type == ClaimTypes.Email and x.value == User.email,), True,),
    ((lambda x: x.type == ClaimTypes.Email and x.value == "User.email",), False,),
    ((lambda x: x.type == ClaimTypes.SecurityStamp and x.value == User.username,), False,),
})
def test_principal_has_claim(_match, result, principal):
    assert principal.has_claim(*_match) is result  # noqa


@pytest.mark.parametrize("role_name, result", {
    ("admin", True,),
    ("user", True,),
    ("Admin", False,),
    ("manager", False,)
})
def test_principal_is_in_role(role_name, result, principal):
    assert principal.is_in_role(role_name) is result


@pytest.mark.parametrize("role_name, result", {
    (("admin", "user",), True,),
    (("manager", "user",), False,),
    (("admin", "superuser",), False,)
})
def test_principal_is_in_all_roles(role_name, result, principal):
    assert principal.is_in_roles(*role_name) is result


@pytest.mark.parametrize("role_name, result", {
    (("admin", "user",), True,),
    (("superuser", "user",), True,),
    (("admin", "Manager",), True,),
    (("Admin", "Manager",), False,)
})
def test_principal_is_in_any_roles(role_name, result, principal):
    assert principal.is_in_roles(*role_name, mode='any') is result
