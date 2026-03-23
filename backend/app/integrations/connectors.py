"""
CYPHER AI Integration Layer
Conectores para SIEMs, EDRs, XDRs, Firewalls e Cloud Providers
"""
from abc import ABC, abstractmethod
from typing import Optional
import httpx
import structlog

logger = structlog.get_logger()


# ────────────────────────────────────────────────────────────────
# BASE CONNECTOR
# ────────────────────────────────────────────────────────────────
class BaseConnector(ABC):
    """Contrato base para todos os conectores de integração."""

    def __init__(self, credentials: dict, config: dict = None):
        self.creds = credentials
        self.config = config or {}
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        self._client = httpx.AsyncClient(timeout=30.0)
        return self

    async def __aexit__(self, *args):
        if self._client:
            await self._client.aclose()

    @abstractmethod
    async def health_check(self) -> dict:
        """Testa conectividade e autenticação."""
        pass

    @abstractmethod
    async def fetch_alerts(self, since_minutes: int = 60) -> list[dict]:
        """Busca alertas recentes."""
        pass


# ────────────────────────────────────────────────────────────────
# SIEM CONNECTORS
# ────────────────────────────────────────────────────────────────
class SplunkConnector(BaseConnector):
    """Splunk Enterprise / Splunk Cloud via REST API."""

    async def health_check(self) -> dict:
        async with httpx.AsyncClient(verify=True, timeout=10) as client:
            try:
                resp = await client.get(
                    f"{self.creds['url']}/services/server/info",
                    headers={"Authorization": f"Bearer {self.creds['token']}"},
                    params={"output_mode": "json"},
                )
                return {"status": "healthy", "version": resp.json().get("generator", {}).get("version")}
            except Exception as e:
                return {"status": "offline", "error": str(e)}

    async def fetch_alerts(self, since_minutes: int = 60) -> list[dict]:
        """Busca alertas disparados via Splunk alerts/fired_alerts."""
        async with httpx.AsyncClient(verify=True, timeout=30) as client:
            resp = await client.get(
                f"{self.creds['url']}/services/alerts/fired_alerts",
                headers={"Authorization": f"Bearer {self.creds['token']}"},
                params={"output_mode": "json", "count": 100},
            )
            resp.raise_for_status()
            entries = resp.json().get("entry", [])
            return [self._normalize_alert(e) for e in entries]

    async def run_search(self, spl_query: str, earliest: str = "-1h") -> list[dict]:
        """Executa uma busca SPL e retorna resultados."""
        async with httpx.AsyncClient(verify=True, timeout=60) as client:
            # Cria job de busca
            create_resp = await client.post(
                f"{self.creds['url']}/services/search/jobs",
                headers={"Authorization": f"Bearer {self.creds['token']}"},
                data={
                    "search": f"search {spl_query}",
                    "earliest_time": earliest,
                    "output_mode": "json",
                },
            )
            sid = create_resp.json()["sid"]

            # Aguarda completar (simplificado — em produção use polling async)
            import asyncio
            await asyncio.sleep(3)

            # Pega resultados
            results_resp = await client.get(
                f"{self.creds['url']}/services/search/jobs/{sid}/results",
                headers={"Authorization": f"Bearer {self.creds['token']}"},
                params={"output_mode": "json", "count": 1000},
            )
            return results_resp.json().get("results", [])

    def _normalize_alert(self, raw: dict) -> dict:
        content = raw.get("content", {})
        return {
            "source": "splunk",
            "external_id": raw.get("name"),
            "title": raw.get("name", "Splunk Alert"),
            "description": content.get("description", ""),
            "severity": self._map_severity(content.get("severity", "medium")),
            "occurred_at": content.get("trigger_time"),
            "raw_data": raw,
        }

    def _map_severity(self, splunk_sev: str) -> str:
        mapping = {"1": "info", "2": "low", "3": "medium", "4": "high", "5": "critical"}
        return mapping.get(str(splunk_sev), splunk_sev.lower())


class ElasticConnector(BaseConnector):
    """Elasticsearch + Kibana SIEM via REST API."""

    async def health_check(self) -> dict:
        async with httpx.AsyncClient(timeout=10) as client:
            try:
                auth = (self.creds.get("user"), self.creds.get("password")) if self.creds.get("user") else None
                headers = {"Authorization": f"ApiKey {self.creds['api_key']}"} if self.creds.get("api_key") else {}
                resp = await client.get(f"{self.creds['url']}/_cluster/health", auth=auth, headers=headers)
                data = resp.json()
                return {"status": "healthy" if data.get("status") != "red" else "degraded", "cluster_status": data.get("status")}
            except Exception as e:
                return {"status": "offline", "error": str(e)}

    async def fetch_alerts(self, since_minutes: int = 60) -> list[dict]:
        """Busca alertas do índice .siem-signals-* ou .alerts-security.*."""
        async with httpx.AsyncClient(timeout=30) as client:
            auth = (self.creds.get("user"), self.creds.get("password")) if self.creds.get("user") else None
            headers = {"Authorization": f"ApiKey {self.creds['api_key']}"} if self.creds.get("api_key") else {}
            query = {
                "query": {
                    "bool": {
                        "filter": [
                            {"range": {"@timestamp": {"gte": f"now-{since_minutes}m"}}},
                            {"term": {"kibana.alert.workflow_status": "open"}},
                        ]
                    }
                },
                "size": 100,
                "sort": [{"@timestamp": {"order": "desc"}}],
            }
            index = self.config.get("alerts_index", ".alerts-security.*")
            resp = await client.post(
                f"{self.creds['url']}/{index}/_search",
                json=query, auth=auth, headers=headers,
            )
            resp.raise_for_status()
            hits = resp.json().get("hits", {}).get("hits", [])
            return [self._normalize_alert(h) for h in hits]

    def _normalize_alert(self, raw: dict) -> dict:
        src = raw.get("_source", {})
        return {
            "source": "elastic",
            "external_id": raw.get("_id"),
            "title": src.get("kibana.alert.rule.name", "Elastic Alert"),
            "description": src.get("kibana.alert.reason", ""),
            "severity": src.get("kibana.alert.severity", "medium").lower(),
            "occurred_at": src.get("@timestamp"),
            "raw_data": raw,
        }


class MicrosoftSentinelConnector(BaseConnector):
    """Microsoft Sentinel via Azure Monitor / Security Insights API."""

    _token: Optional[str] = None

    async def _get_token(self) -> str:
        if self._token:
            return self._token
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"https://login.microsoftonline.com/{self.creds['tenant_id']}/oauth2/v2.0/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.creds["client_id"],
                    "client_secret": self.creds["client_secret"],
                    "scope": "https://management.azure.com/.default",
                },
            )
            self._token = resp.json()["access_token"]
            return self._token

    async def health_check(self) -> dict:
        try:
            token = await self._get_token()
            return {"status": "healthy", "token_obtained": True}
        except Exception as e:
            return {"status": "offline", "error": str(e)}

    async def fetch_alerts(self, since_minutes: int = 60) -> list[dict]:
        token = await self._get_token()
        subscription = self.creds["subscription_id"]
        rg = self.creds["resource_group"]
        workspace = self.creds["workspace_name"]

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"https://management.azure.com/subscriptions/{subscription}/resourceGroups/{rg}"
                f"/providers/Microsoft.OperationalInsights/workspaces/{workspace}"
                f"/providers/Microsoft.SecurityInsights/incidents",
                headers={"Authorization": f"Bearer {token}"},
                params={"api-version": "2023-11-01", "$filter": "properties/status eq 'New'", "$top": 100},
            )
            resp.raise_for_status()
            items = resp.json().get("value", [])
            return [self._normalize_alert(i) for i in items]

    def _normalize_alert(self, raw: dict) -> dict:
        props = raw.get("properties", {})
        sev_map = {"High": "high", "Medium": "medium", "Low": "low", "Informational": "info"}
        return {
            "source": "ms_sentinel",
            "external_id": raw.get("name"),
            "title": props.get("title", "Sentinel Incident"),
            "description": props.get("description", ""),
            "severity": sev_map.get(props.get("severity", "Medium"), "medium"),
            "occurred_at": props.get("createdTimeUtc"),
            "raw_data": raw,
        }


# ────────────────────────────────────────────────────────────────
# EDR / XDR CONNECTORS
# ────────────────────────────────────────────────────────────────
class CrowdStrikeConnector(BaseConnector):
    """CrowdStrike Falcon via OAuth2 API."""

    _token: Optional[str] = None

    async def _authenticate(self) -> str:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"{self.creds.get('base_url', 'https://api.crowdstrike.com')}/oauth2/token",
                data={
                    "client_id": self.creds["client_id"],
                    "client_secret": self.creds["client_secret"],
                },
            )
            resp.raise_for_status()
            self._token = resp.json()["access_token"]
            return self._token

    async def health_check(self) -> dict:
        try:
            await self._authenticate()
            return {"status": "healthy"}
        except Exception as e:
            return {"status": "offline", "error": str(e)}

    async def fetch_alerts(self, since_minutes: int = 60) -> list[dict]:
        token = await self._authenticate()
        base = self.creds.get("base_url", "https://api.crowdstrike.com")
        from datetime import datetime, timedelta, timezone
        since = (datetime.now(timezone.utc) - timedelta(minutes=since_minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")

        async with httpx.AsyncClient(timeout=30) as client:
            # Get detection IDs
            ids_resp = await client.get(
                f"{base}/detects/queries/detects/v1",
                headers={"Authorization": f"Bearer {token}"},
                params={"filter": f"created_timestamp:>'{since}'", "limit": 100},
            )
            ids = ids_resp.json().get("resources", [])
            if not ids:
                return []

            # Get detection details
            details_resp = await client.post(
                f"{base}/detects/entities/summaries/GET/v1",
                headers={"Authorization": f"Bearer {token}"},
                json={"ids": ids},
            )
            detections = details_resp.json().get("resources", [])
            return [self._normalize_alert(d) for d in detections]

    async def isolate_host(self, device_id: str) -> dict:
        """Isola um host da rede via CrowdStrike RTR."""
        token = await self._authenticate()
        base = self.creds.get("base_url", "https://api.crowdstrike.com")
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{base}/devices/entities/devices-actions/v2",
                headers={"Authorization": f"Bearer {token}"},
                params={"action_name": "contain"},
                json={"ids": [device_id]},
            )
            return {"success": resp.status_code == 202, "response": resp.json()}

    async def block_hash(self, sha256: str, comment: str = "Blocked by CYPHER AI") -> dict:
        """Bloqueia um hash via Custom IOA / ML exclusion."""
        token = await self._authenticate()
        base = self.creds.get("base_url", "https://api.crowdstrike.com")
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{base}/iocs/entities/indicators/v1",
                headers={"Authorization": f"Bearer {token}"},
                json={"indicators": [{"type": "sha256", "value": sha256, "action": "prevent", "comment": comment}]},
            )
            return {"success": resp.status_code in (200, 201), "response": resp.json()}

    def _normalize_alert(self, raw: dict) -> dict:
        sev_map = {1: "low", 2: "medium", 3: "high", 4: "critical"}
        return {
            "source": "crowdstrike",
            "external_id": raw.get("detection_id"),
            "title": raw.get("behaviors", [{}])[0].get("display_name", "CrowdStrike Detection"),
            "description": raw.get("behaviors", [{}])[0].get("description", ""),
            "severity": sev_map.get(raw.get("max_severity_displayname", 2), "medium"),
            "occurred_at": raw.get("created_timestamp"),
            "raw_data": raw,
        }


class SentinelOneConnector(BaseConnector):
    """SentinelOne via REST API v2.1."""

    async def health_check(self) -> dict:
        async with httpx.AsyncClient(timeout=10) as client:
            try:
                resp = await client.get(
                    f"{self.creds['url']}/web/api/v2.1/system/status",
                    headers={"Authorization": f"ApiToken {self.creds['api_token']}"},
                )
                return {"status": "healthy", "health": resp.json().get("data", {}).get("health")}
            except Exception as e:
                return {"status": "offline", "error": str(e)}

    async def fetch_alerts(self, since_minutes: int = 60) -> list[dict]:
        from datetime import datetime, timedelta, timezone
        since = (datetime.now(timezone.utc) - timedelta(minutes=since_minutes)).isoformat()
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{self.creds['url']}/web/api/v2.1/threats",
                headers={"Authorization": f"ApiToken {self.creds['api_token']}"},
                params={"createdAt__gt": since, "limit": 100, "sortBy": "createdAt", "sortOrder": "desc"},
            )
            resp.raise_for_status()
            return [self._normalize_alert(t) for t in resp.json().get("data", [])]

    async def isolate_agent(self, agent_id: str) -> dict:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{self.creds['url']}/web/api/v2.1/agents/actions/disconnect",
                headers={"Authorization": f"ApiToken {self.creds['api_token']}"},
                json={"filter": {"ids": [agent_id]}},
            )
            return {"success": resp.status_code == 200, "response": resp.json()}

    def _normalize_alert(self, raw: dict) -> dict:
        sev_map = {"E_NOTICE": "info", "E_WARNING": "low", "E_THREAT": "high", "E_CRITICAL": "critical"}
        return {
            "source": "sentinelone",
            "external_id": raw.get("id"),
            "title": raw.get("threatInfo", {}).get("threatName", "SentinelOne Threat"),
            "description": raw.get("threatInfo", {}).get("classification", ""),
            "severity": sev_map.get(raw.get("threatInfo", {}).get("confidenceLevel"), "medium"),
            "occurred_at": raw.get("createdAt"),
            "raw_data": raw,
        }


# ────────────────────────────────────────────────────────────────
# FIREWALL CONNECTORS
# ────────────────────────────────────────────────────────────────
class FortinetConnector(BaseConnector):
    """FortiGate via FortiOS REST API."""

    async def health_check(self) -> dict:
        async with httpx.AsyncClient(verify=True, timeout=10) as client:
            try:
                resp = await client.get(
                    f"{self.creds['url']}/api/v2/monitor/system/status",
                    headers={"Authorization": f"Bearer {self.creds['api_key']}"},
                )
                data = resp.json()
                return {"status": "healthy", "version": data.get("results", {}).get("version")}
            except Exception as e:
                return {"status": "offline", "error": str(e)}

    async def fetch_alerts(self, since_minutes: int = 60) -> list[dict]:
        """Busca logs de ameaças do FortiGate."""
        async with httpx.AsyncClient(verify=True, timeout=30) as client:
            resp = await client.get(
                f"{self.creds['url']}/api/v2/log/disk/threat",
                headers={"Authorization": f"Bearer {self.creds['api_key']}"},
                params={"rows": 100},
            )
            logs = resp.json().get("results", [])
            return [self._normalize_log(l) for l in logs]

    async def block_ip(self, ip: str, comment: str = "Blocked by CYPHER AI") -> dict:
        """Adiciona IP à address group de bloqueio."""
        async with httpx.AsyncClient(verify=True, timeout=30) as client:
            # Cria address object
            await client.post(
                f"{self.creds['url']}/api/v2/cmdb/firewall/address",
                headers={"Authorization": f"Bearer {self.creds['api_key']}"},
                json={"name": f"CYPHER AI-BLOCK-{ip}", "type": "ipmask", "subnet": f"{ip}/32", "comment": comment},
            )
            return {"success": True, "ip": ip, "action": "address_created"}

    async def fetch_logs(self, log_type: str = "traffic", rows: int = 500) -> list[dict]:
        async with httpx.AsyncClient(verify=True, timeout=30) as client:
            resp = await client.get(
                f"{self.creds['url']}/api/v2/log/disk/{log_type}",
                headers={"Authorization": f"Bearer {self.creds['api_key']}"},
                params={"rows": rows},
            )
            return resp.json().get("results", [])

    def _normalize_log(self, raw: dict) -> dict:
        return {
            "source": "fortinet",
            "external_id": raw.get("logid"),
            "title": raw.get("msg", "FortiGate Threat"),
            "description": f"Action: {raw.get('action')} | Src: {raw.get('srcip')} | Dst: {raw.get('dstip')}",
            "severity": raw.get("level", "medium").lower(),
            "occurred_at": raw.get("date"),
            "raw_data": raw,
        }


class PaloAltoConnector(BaseConnector):
    """Palo Alto Networks PAN-OS via XML/REST API."""

    async def health_check(self) -> dict:
        async with httpx.AsyncClient(verify=True, timeout=10) as client:
            try:
                resp = await client.get(
                    f"{self.creds['url']}/api/",
                    params={"type": "op", "cmd": "<show><system><info></info></system></show>", "key": self.creds["api_key"]},
                )
                return {"status": "healthy" if resp.status_code == 200 else "degraded"}
            except Exception as e:
                return {"status": "offline", "error": str(e)}

    async def fetch_alerts(self, since_minutes: int = 60) -> list[dict]:
        async with httpx.AsyncClient(verify=True, timeout=30) as client:
            resp = await client.get(
                f"{self.creds['url']}/api/",
                params={
                    "type": "log", "log-type": "threat",
                    "query": f"(receive_time geq '{since_minutes} minutes ago')",
                    "nlogs": 100, "key": self.creds["api_key"],
                },
            )
            # Parse XML response
            import xml.etree.ElementTree as ET
            root = ET.fromstring(resp.text)
            logs = root.findall(".//entry")
            return [self._normalize_log(log) for log in logs]

    async def block_ip(self, ip: str) -> dict:
        """Adiciona IP ao Dynamic Address Group via API."""
        async with httpx.AsyncClient(verify=True, timeout=15) as client:
            resp = await client.post(
                f"{self.creds['url']}/api/",
                params={
                    "type": "config", "action": "set",
                    "xpath": f"/config/devices/entry/vsys/entry/address/entry[@name='CYPHER AI-BLOCK-{ip}']",
                    "element": f"<ip-netmask>{ip}/32</ip-netmask>",
                    "key": self.creds["api_key"],
                },
            )
            return {"success": "<status>success</status>" in resp.text}

    def _normalize_log(self, raw) -> dict:
        return {
            "source": "palo_alto",
            "external_id": raw.findtext("seqno"),
            "title": raw.findtext("threatid", "Palo Alto Threat"),
            "description": f"Src: {raw.findtext('src')} | Dst: {raw.findtext('dst')} | App: {raw.findtext('app')}",
            "severity": raw.findtext("severity", "medium").lower(),
            "occurred_at": raw.findtext("receive_time"),
            "raw_data": {"tag": raw.tag, "attrib": raw.attrib},
        }


# ────────────────────────────────────────────────────────────────
# CLOUD CONNECTORS
# ────────────────────────────────────────────────────────────────
class AWSGuardDutyConnector(BaseConnector):
    """AWS GuardDuty + Security Hub via boto3."""

    async def health_check(self) -> dict:
        try:
            import boto3
            session = boto3.Session(
                aws_access_key_id=self.creds.get("access_key_id"),
                aws_secret_access_key=self.creds.get("secret_access_key"),
                region_name=self.creds.get("region", "us-east-1"),
            )
            gd = session.client("guardduty")
            gd.list_detectors()
            return {"status": "healthy"}
        except Exception as e:
            return {"status": "offline", "error": str(e)}

    async def fetch_alerts(self, since_minutes: int = 60) -> list[dict]:
        import boto3
        from datetime import datetime, timedelta, timezone
        import asyncio

        session = boto3.Session(
            aws_access_key_id=self.creds.get("access_key_id"),
            aws_secret_access_key=self.creds.get("secret_access_key"),
            region_name=self.creds.get("region", "us-east-1"),
        )
        gd = session.client("guardduty")
        since = (datetime.now(timezone.utc) - timedelta(minutes=since_minutes)).timestamp()

        # Get detectors
        detectors = gd.list_detectors()["DetectorIds"]
        if not detectors:
            return []

        detector_id = detectors[0]
        findings_resp = gd.list_findings(
            DetectorId=detector_id,
            FindingCriteria={"Criterion": {"updatedAt": {"Gte": int(since * 1000)}}},
            MaxResults=100,
        )
        finding_ids = findings_resp.get("FindingIds", [])
        if not finding_ids:
            return []

        findings = gd.get_findings(DetectorId=detector_id, FindingIds=finding_ids)
        return [self._normalize_finding(f) for f in findings.get("Findings", [])]

    def _normalize_finding(self, raw: dict) -> dict:
        sev = raw.get("Severity", 5)
        if sev >= 7: severity = "high"
        elif sev >= 4: severity = "medium"
        else: severity = "low"
        return {
            "source": "aws_guardduty",
            "external_id": raw.get("Id"),
            "title": raw.get("Title", "GuardDuty Finding"),
            "description": raw.get("Description", ""),
            "severity": severity,
            "occurred_at": raw.get("UpdatedAt"),
            "raw_data": raw,
        }


# ────────────────────────────────────────────────────────────────
# NOTIFICATION CONNECTORS
# ────────────────────────────────────────────────────────────────
class SlackConnector:
    def __init__(self, token: str, default_channel: str = "#security-incidents"):
        self.token = token
        self.channel = default_channel

    async def send_incident_alert(self, incident: dict) -> dict:
        sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(
            incident.get("severity", "medium"), "⚪"
        )
        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": f"{sev_emoji} CYPHER AI — Novo Incidente"}},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*ID:*\n{incident.get('ref')}"},
                {"type": "mrkdwn", "text": f"*Severidade:*\n{incident.get('severity', '').upper()}"},
                {"type": "mrkdwn", "text": f"*Cliente:*\n{incident.get('client_name', 'N/A')}"},
                {"type": "mrkdwn", "text": f"*Título:*\n{incident.get('title')}"},
            ]},
        ]
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                "https://slack.com/api/chat.postMessage",
                headers={"Authorization": f"Bearer {self.token}"},
                json={"channel": self.channel, "blocks": blocks},
            )
            return resp.json()


class JiraConnector:
    def __init__(self, url: str, user: str, api_token: str, project: str = "SEC"):
        self.url = url
        self.auth = (user, api_token)
        self.project = project

    async def create_ticket(self, incident: dict) -> dict:
        priority_map = {"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low"}
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{self.url}/rest/api/3/issue",
                auth=self.auth,
                json={
                    "fields": {
                        "project": {"key": self.project},
                        "summary": f"[{incident.get('ref')}] {incident.get('title')}",
                        "description": {
                            "type": "doc", "version": 1,
                            "content": [{"type": "paragraph", "content": [
                                {"type": "text", "text": incident.get("description", "Ver CYPHER AI para detalhes.")}
                            ]}]
                        },
                        "issuetype": {"name": "Security Incident"},
                        "priority": {"name": priority_map.get(incident.get("severity", "medium"), "Medium")},
                        "labels": ["cypher", "security-incident", incident.get("severity", "medium")],
                    }
                },
            )
            resp.raise_for_status()
            data = resp.json()
            return {"ticket_id": data.get("key"), "url": f"{self.url}/browse/{data.get('key')}"}


# ────────────────────────────────────────────────────────────────
# ENRICHMENT
# ────────────────────────────────────────────────────────────────
class VirusTotalEnricher:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base = "https://www.virustotal.com/api/v3"

    async def check_ip(self, ip: str) -> dict:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"{self.base}/ip_addresses/{ip}",
                headers={"x-apikey": self.api_key},
            )
            if resp.status_code != 200:
                return {}
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "reputation": data.get("reputation", 0),
                "country": data.get("country"),
                "as_owner": data.get("as_owner"),
            }

    async def check_hash(self, sha256: str) -> dict:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"{self.base}/files/{sha256}",
                headers={"x-apikey": self.api_key},
            )
            if resp.status_code != 200:
                return {}
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "name": data.get("meaningful_name"),
                "type": data.get("type_description"),
                "size": data.get("size"),
                "tags": data.get("tags", []),
            }

    async def check_domain(self, domain: str) -> dict:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"{self.base}/domains/{domain}",
                headers={"x-apikey": self.api_key},
            )
            if resp.status_code != 200:
                return {}
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "reputation": data.get("reputation", 0),
                "categories": data.get("categories", {}),
                "registrar": data.get("registrar"),
            }


# ────────────────────────────────────────────────────────────────
# CONNECTOR FACTORY
# ────────────────────────────────────────────────────────────────
CONNECTOR_MAP = {
    "splunk": SplunkConnector,
    "elastic": ElasticConnector,
    "ms_sentinel": MicrosoftSentinelConnector,
    "crowdstrike": CrowdStrikeConnector,
    "sentinelone": SentinelOneConnector,
    "fortinet": FortinetConnector,
    "palo_alto": PaloAltoConnector,
    "aws_guardduty": AWSGuardDutyConnector,
}


def get_connector(integration_type: str, credentials: dict, config: dict = None) -> BaseConnector:
    cls = CONNECTOR_MAP.get(integration_type)
    if not cls:
        raise ValueError(f"Integração não suportada: {integration_type}")
    return cls(credentials, config)
