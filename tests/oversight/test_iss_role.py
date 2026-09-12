"""iss_role enum + mapping."""

from overturo.oversight.iss_role import (
    ISS_ROLE_TO_TRUST_WEIGHT,
    ISS_ROLES,
    is_valid_iss_role,
)


def test_iss_roles_closed_enum():
    assert ISS_ROLES == ("authorizer", "witness", "approval_url_signer")


def test_iss_role_to_trust_weight_covers_every_role():
    for role in ISS_ROLES:
        assert role in ISS_ROLE_TO_TRUST_WEIGHT


def test_authorizer_maps_to_strong():
    assert ISS_ROLE_TO_TRUST_WEIGHT["authorizer"] == "strong"


def test_witness_maps_to_witness_only():
    assert ISS_ROLE_TO_TRUST_WEIGHT["witness"] == "witness_only"


def test_approval_url_signer_maps_to_approval_url():
    assert ISS_ROLE_TO_TRUST_WEIGHT["approval_url_signer"] == "approval_url"


def test_is_valid_iss_role():
    assert is_valid_iss_role("authorizer") is True
    assert is_valid_iss_role("witness") is True
    assert is_valid_iss_role("rogue") is False
    assert is_valid_iss_role(123) is False
    assert is_valid_iss_role(None) is False
