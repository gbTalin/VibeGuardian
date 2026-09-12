from cg_threat_intel.services.exa_intelligence import extract_exa_intelligence_lead


def test_extracts_identifiers_and_citations_from_completed_exa_run() -> None:
    lead = extract_exa_intelligence_lead(
        {
            "output": {
                "content": {"advisory": "CVE-2026-12345 affects an observed dependency."},
                "results": [{"url": "https://vendor.example/advisory"}],
                "grounding": [
                    {"citations": [{"url": "https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc"}]}
                ],
            }
        }
    )

    assert lead.candidate_identifiers == ["CVE-2026-12345"]
    assert lead.source_urls == [
        "https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc",
        "https://vendor.example/advisory",
    ]
