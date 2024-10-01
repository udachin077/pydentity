from pydentity.utils import is_none_or_empty


def test_is_none_or_empty():
    assert is_none_or_empty("") is True
    assert is_none_or_empty(" ") is True
    assert is_none_or_empty(None) is True
    assert is_none_or_empty("None") is False
    assert is_none_or_empty("_") is False
