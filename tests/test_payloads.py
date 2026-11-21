from redteam.payloads import ATTACKS, BENIGN
from redteam.payloads_heldout import ATTACKS_HELDOUT, BENIGN_HELDOUT

CATS = {"direct_injection", "jailbreak_narrative", "indirect_rag", "markdown_exfil"}


def test_ids_unique_across_sets():
    ids = [p.id for p in ATTACKS + BENIGN + ATTACKS_HELDOUT + BENIGN_HELDOUT]
    assert len(ids) == len(set(ids))


def test_categories_valid_and_covered():
    for attacks in (ATTACKS, ATTACKS_HELDOUT):
        assert {p.category for p in attacks} == CATS


def test_benign_have_expected_keywords():
    assert all(p.expect for p in BENIGN + BENIGN_HELDOUT)


def test_heldout_disjoint_from_main():
    assert not {p.text for p in ATTACKS} & {p.text for p in ATTACKS_HELDOUT}
