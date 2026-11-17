import pytest

from audit.log_chain import (
    canonical_event,
    event_hash,
    verify_chain,
    redact,
    anchor
)


def test_canonical_sorted():
    assert canonical_event({'b': 2, 'a': 1}) == '{"a":1,"b":2}'

def test_canonical_stable():
    assert canonical_event({'a': 1, 'b': 2}) == canonical_event({'b': 2, 'a': 1})

def test_hash_stable():
    assert event_hash('prev', {'a': 1}) == event_hash('prev', {'a': 1})

def test_hash_field():
    assert event_hash('prev', {'a': 1}) != event_hash('prev', {'a': 2})

def test_verify_valid():
    chain = [{'seq': 1, 'hash': event_hash('0', {'seq': 1})}, {'seq': 2, 'hash': event_hash(event_hash('0', {'seq': 1}), {'seq': 2})}]
    assert verify_chain(chain) is True

def test_verify_tamper():
    chain = [{'seq': 1, 'hash': 'bad'}]
    assert verify_chain(chain) is False

def test_verify_gap():
    chain = [{'seq': 1, 'hash': 'a'}, {'seq': 3, 'hash': 'b'}]
    assert verify_chain(chain) is False

def test_redact_phone():
    assert '138****1234' in redact('call 13800181234')

def test_redact_id():
    assert '110101********1234' in redact('id 110101199001011234')

def test_redact_keep():
    assert redact('hello') == 'hello'

def test_anchor():
    assert anchor('head', {'head': True}) is True

def test_empty_chain():
    assert verify_chain([]) is True

def test_clock_order():
    chain = [{'seq': 2, 'time': 90}, {'seq': 1, 'time': 100}]
    assert verify_chain(chain) is False

def test_duplicate_seq():
    chain = [{'seq': 1, 'hash': 'a'}, {'seq': 1, 'hash': 'b'}]
    assert verify_chain(chain) is False

def test_head():
    assert anchor('head', {'head': False}) is False
