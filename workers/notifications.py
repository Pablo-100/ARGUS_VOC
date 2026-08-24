"""Notification engine (Feature 11).

Clean provider-adapter architecture - vulnerability/ticket logic never talks
to Telegram or SMTP directly. Providers are selected via env:

    NOTIFICATION_PROVIDERS=telegram,email,log     (comma-separated; 'log' is
                                                   always active as fallback)

    TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID   -> TelegramProvider
    SMTP_HOST/PORT/USER/PASS/FROM/TO        -> EmailProvider

Events supported:
    * critical vulnerability detected  (notify_critical_vulnerability)
    * SLA overdue                      (portal enqueues request doc)
    * ticket assignment                (portal enqueues request doc)
    * vulnerability resolved           (verification sweep outcome)
    * vulnerability reopened           (verification sweep outcome)

The portal cannot reach providers directly (providers live in the worker
image), so portal-side events are written into ES as
`notification-request` documents and delivered by the
tasks.drain_notification_queue beat task.
"""
import logging
import os
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Provider abstraction
# ---------------------------------------------------------------------------
class NotificationProvider(ABC):
    name = 'abstract'

    @abstractmethod
    def send(self, subject: str, body: str) -> bool:
        """Deliver one notification. Return True on success."""


class LogProvider(NotificationProvider):
    """Always-available fallback so no event is ever silently dropped."""

    name = 'log'

    def send(self, subject, body):
        logger.info(f'[NOTIFY:{self.name}] {subject}: {body[:400]}')
        return True


class TelegramProvider(NotificationProvider):
    name = 'telegram'

    def __init__(self):
        self.token = os.getenv('TELEGRAM_BOT_TOKEN', '')
        self.chat_id = os.getenv('TELEGRAM_CHAT_ID', '')

    def available(self):
        return bool(self.token and self.chat_id)

    def send(self, subject, body):
        if not self.available():
            logger.warning('[NOTIFY:telegram] token/chat not configured - skipped')
            return False
        import requests
        try:
            r = requests.post(
                f'https://api.telegram.org/bot{self.token}/sendMessage',
                json={'chat_id': self.chat_id,
                      'text': f'*{subject}*\n{body}',
                      'parse_mode': 'Markdown'},
                timeout=10)
            return r.status_code == 200
        except Exception as e:
            logger.warning(f'[NOTIFY:telegram] delivery failed: {e}')
            return False


class EmailProvider(NotificationProvider):
    name = 'email'

    def __init__(self):
        self.host = os.getenv('SMTP_HOST', '')
        self.port = int(os.getenv('SMTP_PORT', '587'))
        self.user = os.getenv('SMTP_USER', '')
        self.password = os.getenv('SMTP_PASS', '')
        self.from_addr = os.getenv('SMTP_FROM', self.user)
        self.to_addrs = [a.strip() for a in os.getenv('SMTP_TO', '').split(',') if a.strip()]

    def available(self):
        return bool(self.host and self.to_addrs)

    def send(self, subject, body):
        if not self.available():
            logger.warning('[NOTIFY:email] SMTP_HOST/SMTP_TO not configured - skipped')
            return False
        import smtplib
        from email.mime.text import MIMEText
        msg = MIMEText(body, 'plain', 'utf-8')
        msg['Subject'] = subject
        msg['From'] = self.from_addr
        msg['To'] = ', '.join(self.to_addrs)
        try:
            if os.getenv('SMTP_SSL', '').lower() == 'true':
                server = smtplib.SMTP_SSL(self.host, self.port, timeout=15)
            else:
                server = smtplib.SMTP(self.host, self.port, timeout=15)
                if self.user:
                    server.starttls()
                    server.login(self.user, self.password)
            try:
                server.sendmail(self.from_addr, self.to_addrs, msg.as_string())
            finally:
                server.quit()
            return True
        except Exception as e:
            logger.warning(f'[NOTIFY:email] delivery failed: {e}')
            return False


_PROVIDERS = None


def get_providers():
    global _PROVIDERS
    if _PROVIDERS is None:
        selected = [p.strip() for p in
                    os.getenv('NOTIFICATION_PROVIDERS', 'log').split(',') if p.strip()]
        registry = {'log': LogProvider, 'telegram': TelegramProvider, 'email': EmailProvider}
        _PROVIDERS = []
        for name in selected:
            cls = registry.get(name.lower())
            if cls is None:
                logger.warning(f'unknown notification provider {name!r} - ignored')
                continue
            prov = cls()
            _PROVIDERS.append(prov)
        if not _PROVIDERS:
            _PROVIDERS = [LogProvider()]
    return _PROVIDERS


def broadcast(subject, body):
    """Send through every configured provider; True if at least one succeeded."""
    ok = False
    for p in get_providers():
        try:
            ok = p.send(subject, body) or ok
        except Exception as e:
            logger.warning(f'provider {p.name} raised: {e}')
    return ok


# ---------------------------------------------------------------------------
# Event formatters + entry points
# ---------------------------------------------------------------------------

def notify_critical_vulnerability(vuln, host, scan_id=''):
    """Critical finding detected by the pipeline (risk >= threshold)."""
    risk = float(vuln.get('risk_score') or 0)
    severity = str(vuln.get('severity') or '').lower()
    threshold = float(os.getenv('NOTIFY_CRITICAL_RISK_THRESHOLD', '9.0'))
    if severity != 'critical' and risk < threshold:
        return False

    ctx = vuln.get('asset_context') or {}
    factors = vuln.get('risk_breakdown') or {}
    lines = [
        f"CRITICAL VULNERABILITY DETECTED",
        "",
        f"CVE:       {vuln.get('cve', 'N/A')}",
        f"Asset:     {host}",
        f"IP:        {host}",
        f"Port:      {vuln.get('port', 'N/A')} ({vuln.get('service', 'N/A')})",
        f"Risk:      {risk:.1f}/10 ({vuln.get('severity', '?')})",
        f"CVSS:      {vuln.get('cvss', 'N/A')}",
        f"EPSS:      {vuln.get('epss_score', 'N/A')}",
        f"KEV:       {'YES - actively exploited' if vuln.get('in_kev') else 'no'}",
        f"Exposure:  internet-exposed={ctx.get('internet_exposed')}, "
        f"criticality={ctx.get('criticality', '?')}/5",
    ]
    if vuln.get('reopened'):
        lines.insert(1, '** REOPENED - previously resolved, re-detected **')
    if factors:
        lines.append("")
        lines.append(f"Why this score:")
        for k, v in list(factors.items())[:8]:
            lines.append(f"  - {k}: {v}")
    if scan_id:
        lines.append(f"Scan:      {scan_id}")
    lines.append(f"SLA:       critical findings must be remediated within "
                 f"{os.getenv('SLA_CRITICAL_HOURS', '24')}h")
    lines.append("Ticket:   auto-created in GLPI / portal queue")

    return broadcast('CRITICAL VULNERABILITY DETECTED', '\n'.join(lines))


EVENT_TEMPLATES = {
    'sla_overdue': {
        'subject': 'SLA OVERDUE',
        'fmt': ("Ticket #{ticket_id} [{severity}] {title}\n"
                "Host: {host}  CVE: {cve}\n"
                "Deadline was {sla_deadline} - overdue by {overdue_hours:.0f}h\n"
                "Assignee: {assignee}"),
    },
    'ticket_assigned': {
        'subject': 'TICKET ASSIGNED',
        'fmt': ("Ticket #{ticket_id} [{severity}] {title}\n"
                "Assigned to: {assignee}\n"
                "Reason: {reason}\n"
                "SLA deadline: {sla_deadline}"),
    },
    'vuln_resolved': {
        'subject': 'VULNERABILITY RESOLVED (verified)',
        'fmt': ("Ticket #{ticket_id} resolved after verification.\n"
                "CVE: {cve}  Host: {host}\n{detail}"),
    },
    'vuln_reopened': {
        'subject': 'VULNERABILITY REOPENED',
        'fmt': ("Ticket #{ticket_id} reopened - CVE still present.\n"
                "CVE: {cve}  Host: {host}\n{detail}"),
    },
}


def deliver_request(req):
    """Deliver one portal-enqueued notification request document."""
    event = req.get('event')
    tpl = EVENT_TEMPLATES.get(event)
    if not tpl:
        logger.warning(f'unknown notification event {event!r}')
        return False
    fields = req.get('payload') or {}
    body = tpl['fmt'].format(**fields)
    return broadcast(tpl['subject'], body)
