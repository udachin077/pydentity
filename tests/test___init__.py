import types

from pydenticore.utils import islist, is_none_or_empty


def test_islist():
    assert islist([]) is True
    assert islist(()) is False
    assert islist({}) is False
    CustomList = types.new_class("CustomList", (list,))
    assert islist(CustomList()) is True


def test_is_none_or_empty():
    assert is_none_or_empty("") is True
    assert is_none_or_empty(" ") is True
    assert is_none_or_empty(None) is True
    assert is_none_or_empty("None") is False
    assert is_none_or_empty("_") is False
