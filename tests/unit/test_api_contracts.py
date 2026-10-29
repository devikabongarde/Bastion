import pytest
from baselineguard_contracts.api import AssetCreate, ScanCreate, SiteScope
from pydantic import ValidationError


def test_asset_address_accepts_a_private_ip_or_normalizes_dns() -> None:
    base = {
        "site_id": "16c0cda8-70ba-4b4e-a5dc-4b5d87144a4d",
        "category": "linux",
        "name": "app",
        "port": 22,
        "adapter_id": "linux_ssh",
        "declared_role": "server",
    }
    assert AssetCreate(**base, address="10.20.1.12").address == "10.20.1.12"
    assert AssetCreate(**base, address="HOST.Example.COM.").address == "host.example.com"


@pytest.mark.parametrize(
    "address", ["bad host", "-invalid.example", "", "host.example:22", "bad_name.example"]
)
def test_asset_address_rejects_ambiguous_or_invalid_values(address: str) -> None:
    with pytest.raises(ValidationError):
        AssetCreate(
            site_id="16c0cda8-70ba-4b4e-a5dc-4b5d87144a4d",
            category="linux",
            name="app",
            address=address,
            port=22,
            adapter_id="linux_ssh",
            declared_role="server",
        )


def test_duplicate_targets_are_rejected_before_enqueue() -> None:
    with pytest.raises(ValidationError):
        ScanCreate(
            asset_ids=["16c0cda8-70ba-4b4e-a5dc-4b5d87144a4d"] * 2,
            policy_revision_id="2e6ef888-6013-4c3f-a46f-a116ea5a451c",
            reason="test",
        )


def test_site_scope_requires_specific_network_and_ports() -> None:
    with pytest.raises(ValidationError):
        SiteScope(allowed_cidrs=["0.0.0.0/0"], allowed_ports=[22])
    with pytest.raises(ValidationError):
        SiteScope(allowed_cidrs=["10.0.0.0/8"], allowed_ports=[])
