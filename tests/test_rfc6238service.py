from time import sleep

import pytest

from pydenticore.token_providers.rfc6238service import generate_code, validate_code

tokens = [b"EmailConfirmation", b"Authenticator"]
intervals_false = [1, 2, 3]
modifiers = [b"modifier1", b"email0"]


@pytest.mark.parametrize("token", tokens)
def test_generate_code_true(token):
    code = generate_code(token)
    sleep(2)
    result = validate_code(token, code)
    assert result is True


@pytest.mark.parametrize("token", tokens)
@pytest.mark.parametrize("interval", intervals_false)
def test_generate_code_false(token, interval):
    code = generate_code(token, interval=interval)
    sleep(3)
    result = validate_code(token, code, interval=interval)
    assert result is False


@pytest.mark.parametrize("token", tokens)
@pytest.mark.parametrize("modifier", modifiers)
def test_generate_code_with_modifier(token, modifier):
    code = generate_code(token, modifier)
    sleep(2)
    result = validate_code(token, code, modifier)
    assert result is True
