"""Tests for the FullHunt analyzer."""

from api_app.analyzers_manager.observable_analyzers.fullhunt import FullHunt


def test_fullhunt_analyzer(requests_mock):
    """Test successful domain enrichment from FullHunt."""
    analyzer = FullHunt(config={"api_key": "test_key"})
    requests_mock.get(
        "https://fullhunt.io/api/v1/domain/google.com/details",
        json={"hosts": ["google.com"], "ports": [80, 443]},
    )
    result = analyzer.run("google.com")
    assert "hosts" in result
    assert 80 in result["ports"]
    assert 443 in result["ports"]


def test_fullhunt_not_found(requests_mock):
    """Test handling of 404 Not Found response."""
    analyzer = FullHunt(config={"api_key": "test_key"})
    requests_mock.get(
        "https://fullhunt.io/api/v1/domain/fake.com/details", status_code=404
    )
    result = analyzer.run("fake.com")
    assert result["message"] == "No data found for this domain."
    assert result["status"] == "empty"
