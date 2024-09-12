import asyncio

import pytest

from pydenticore.token_providers.rfc6238service import Rfc6238AuthenticationService


@pytest.mark.asyncio
@pytest.mark.parametrize("security_token_1, security_token_2, modifier_1, modifier_2, interval, result", {
    ("TestRfc6238", "TestRfc6238", "modifier", "modifier", 30, True,),
    ("TestRfc6238", "TestRfc6238_1", "modifier", "modifier", 30, False,),
    ("TestRfc6238", "TestRfc6238", "modifier", "modifier_1", 30, False,),
    ("TestRfc6238", "TestRfc6238", "modifier", "modifier", 1, False,),
})
async def test_generate_and_validate_code(security_token_1, security_token_2, modifier_1, modifier_2, interval, result):
    code = Rfc6238AuthenticationService.generate_code(
        security_token_1.encode(),
        modifier_1.encode(),
        interval
    )
    await asyncio.sleep(2)
    assert Rfc6238AuthenticationService.validate_code(
        security_token_2.encode(),
        code,
        modifier_2.encode(),
        interval
    ) is result
