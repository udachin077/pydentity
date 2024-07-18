import pytest

from pydentity.exc import DataProtectorError
from pydentity.default_personal_data_protector import DefaultPersonalDataProtector


@pytest.mark.parametrize("p1, p2, s1, s2", {
    ("Purpose", "Purpose", None, None,),
    ("Purpose", "Purpose", "None", "None",),
})
def test_data_protector(p1, p2, s1, s2):
    protected_string = DefaultPersonalDataProtector.create_protector(p1, s1).protect("security_string")
    unprotected_string = DefaultPersonalDataProtector.create_protector(p2, s2).unprotect(protected_string)
    assert ("security_string" == unprotected_string) is True


@pytest.mark.parametrize("p1, p2, s1, s2", {
    ("Purpose_1", "Purpose_2", None, None,),
    ("Purpose_2", "Purpose_1", None, None,),
    ("Purpose", "Purpose", "None", None,),
    ("Purpose", "Purpose", None, "None",),
})
def test_data_protector_raises(p1, p2, s1, s2):
    protected_string = DefaultPersonalDataProtector.create_protector(p1, s1).protect("security_string")
    with pytest.raises(DataProtectorError):
        DefaultPersonalDataProtector.create_protector(p2, s2).unprotect(protected_string)
