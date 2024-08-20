import pytest

from pydentity.exc import DataProtectorError
from pydentity.default_personal_data_protector import DefaultPersonalDataProtector


@pytest.mark.parametrize("purpose_1, purpose_2, salt_1, salt_2", {
    ("Purpose", "Purpose", None, None,),
    ("Purpose", "Purpose", "None", "None",),
})
def test_data_protector(purpose_1, purpose_2, salt_1, salt_2):
    protected_string = DefaultPersonalDataProtector(purpose_1, salt_1).protect("security_string")
    unprotected_string = DefaultPersonalDataProtector(purpose_2, salt_2).unprotect(protected_string)
    assert ("security_string" == unprotected_string) is True


@pytest.mark.parametrize("purpose_1, purpose_2, salt_1, salt_2", {
    ("Purpose_1", "Purpose_2", None, None,),
    ("Purpose", "Purpose", "None", "salt1234",),
})
def test_data_protector_raises(purpose_1, purpose_2, salt_1, salt_2):
    protected_string = DefaultPersonalDataProtector(purpose_1, salt_1).protect("security_string")
    with pytest.raises(DataProtectorError):
        DefaultPersonalDataProtector(purpose_2, salt_2).unprotect(protected_string)
