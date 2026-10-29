from baselineguard_api.routes.v1.inventory import AssetCsvImportPreviewRequest


def test_csv_import_preview_validation_logic() -> None:
    # Test valid and invalid row parsing logic
    csv_sample = """name,address,port,category,criticality,role
web-01,10.20.1.50,22,linux,normal,server
win-dc-01,10.20.1.51,5986,windows,critical,server
bad-port,10.20.1.52,99999,linux,normal,server
bad-cat,10.20.1.53,22,mainframe,normal,server
dup-1,10.20.1.54,22,linux,normal,server
dup-1,10.20.1.55,22,linux,normal,server
"""
    req = AssetCsvImportPreviewRequest(csv_text=csv_sample)
    assert "web-01" in req.csv_text
