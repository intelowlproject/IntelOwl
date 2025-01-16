# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


import asyncio

from abuse_whois import get_abuse_contacts

from api_app.analyzers_manager import classes


class AbuseWHOIS(classes.ObservableAnalyzer):

    @classmethod
    def update(cls) -> bool:
        pass

    def _clean_contact_info(self, contact):
        """Remove null values and replace with REDACTED if appropriate"""
        if not any(contact.values()):
            return {"status": "REDACTED FOR PRIVACY"}
        return {k: v for k, v in contact.items() if v is not None}

    def _parse_raw_whois_text(self, raw_text):
        """Extract network information from raw WHOIS text"""
        info = {}
        for line in raw_text.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip()
                value = value.strip()
                if value:
                    info[key] = value

        return info

    def _format_ip_data(self, result):
        """Format IP address WHOIS data"""
        raw_info = self._parse_raw_whois_text(result.records.ip_address.raw_text)

        return {
            "network": {
                "address": result.address,
                "hostname": result.hostname,
                "ip_address": result.ip_address,
                "range": raw_info.get("NetRange"),
                "cidr": raw_info.get("CIDR"),
                "name": raw_info.get("NetName"),
                "type": raw_info.get("NetType"),
                "origin_as": raw_info.get("OriginAS"),
            },
            "organization": {
                "name": raw_info.get("OrgName"),
                "id": raw_info.get("OrgId"),
                "address": raw_info.get("Address"),
                "city": raw_info.get("City"),
                "state": raw_info.get("StateProv"),
                "postal_code": raw_info.get("PostalCode"),
                "country": raw_info.get("Country"),
                "registration_date": raw_info.get("RegDate"),
                "last_updated": raw_info.get("Updated"),
            },
            "contacts": {
                "abuse": {
                    "email": raw_info.get("OrgAbuseEmail"),
                    "phone": raw_info.get("OrgAbusePhone"),
                    "name": raw_info.get("OrgAbuseName"),
                },
                "technical": {
                    "email": raw_info.get("OrgTechEmail"),
                    "phone": raw_info.get("OrgTechPhone"),
                    "name": raw_info.get("OrgTechName"),
                },
            },
        }

    def _format_domain_data(self, result):
        """Format domain WHOIS data"""
        return {
            "domain": {
                "name": result.address,
                "ip_address": result.ip_address,
                "registrar": {
                    "provider": result.registrar.provider if result.registrar else None,
                    "email": result.registrar.address if result.registrar else None,
                    "type": result.registrar.type if result.registrar else None,
                },
            },
            "domain_info": {
                "nameservers": (
                    result.records.domain.name_servers if result.records.domain else []
                ),
                "statuses": (
                    result.records.domain.statuses if result.records.domain else []
                ),
                "expires_at": (
                    result.records.domain.expires_at.isoformat()
                    if result.records.domain and result.records.domain.expires_at
                    else None
                ),
                "updated_at": (
                    result.records.domain.updated_at.isoformat()
                    if result.records.domain and result.records.domain.updated_at
                    else None
                ),
            },
            "contacts": {
                "registrant": self._clean_contact_info(
                    {
                        "organization": (
                            result.records.domain.registrant.organization
                            if result.records.domain
                            else None
                        ),
                        "email": (
                            result.records.domain.registrant.email
                            if result.records.domain
                            else None
                        ),
                        "name": (
                            result.records.domain.registrant.name
                            if result.records.domain
                            else None
                        ),
                        "telephone": (
                            result.records.domain.registrant.telephone
                            if result.records.domain
                            else None
                        ),
                    }
                ),
                "abuse": self._clean_contact_info(
                    {
                        "email": (
                            result.records.domain.abuse.email
                            if result.records.domain
                            else None
                        ),
                        "telephone": (
                            result.records.domain.abuse.telephone
                            if result.records.domain
                            else None
                        ),
                    }
                ),
                "technical": self._clean_contact_info(
                    {
                        "organization": (
                            result.records.domain.tech.organization
                            if result.records.domain
                            else None
                        ),
                        "email": (
                            result.records.domain.tech.email
                            if result.records.domain
                            else None
                        ),
                        "name": (
                            result.records.domain.tech.name
                            if result.records.domain
                            else None
                        ),
                        "telephone": (
                            result.records.domain.tech.telephone
                            if result.records.domain
                            else None
                        ),
                    }
                ),
            },
        }

    async def _get_whois_data(self):
        """Get and format WHOIS data"""
        result = await get_abuse_contacts(self.observable_name)

        # Determine if this is an IP address or domain lookup and format accordingly
        formatted_data = (
            self._format_ip_data(result)
            if result.records.domain is None
            else self._format_domain_data(result)
        )

        # Remove any remaining null values at the top level
        return {k: v for k, v in formatted_data.items() if v is not None}

    def run(self):
        """Run the analyzer"""
        report = asyncio.run(self._get_whois_data())
        return report

    @classmethod
    def _monkeypatch(cls):
        patches = []
        return super()._monkeypatch(patches=patches)
