"""CRUD repositories mapping domain models <-> SQLite rows (PROJECT.md §8).

Hosts dedupe by ``(project_id, ip)`` and ports by ``(host_id, number,
protocol)`` so repeat scans/steps enrich existing rows rather than duplicating
them (the schema enforces both with UNIQUE constraints).
"""

from __future__ import annotations

import json
import sqlite3

from pentui.core.models import Finding, Host, Port, Project, Scan, Service, Severity


class ProjectRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def create(self, project: Project) -> Project:
        cur = self.conn.execute(
            "INSERT INTO project (name, client, notes) VALUES (?, ?, ?);",
            (project.name, project.client, project.notes),
        )
        self.conn.commit()
        assert cur.lastrowid is not None
        created = self.get(cur.lastrowid)
        assert created is not None
        return created

    def get(self, project_id: int) -> Project | None:
        row = self.conn.execute("SELECT * FROM project WHERE id = ?;", (project_id,)).fetchone()
        return self._from_row(row) if row else None

    def list(self) -> list[Project]:
        rows = self.conn.execute("SELECT * FROM project ORDER BY id;").fetchall()
        return [self._from_row(row) for row in rows]

    @staticmethod
    def _from_row(row: sqlite3.Row) -> Project:
        return Project(
            id=row["id"],
            name=row["name"],
            client=row["client"],
            notes=row["notes"],
            created_at=row["created_at"],
        )


class ScanRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def create(self, scan: Scan) -> Scan:
        cur = self.conn.execute(
            "INSERT INTO scan (project_id, tool, profile, command_str, args_json, "
            "status, ran_as_root, step_run_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
            (
                scan.project_id,
                scan.tool,
                scan.profile,
                scan.command_str,
                json.dumps(scan.args),
                scan.status.value,
                int(scan.ran_as_root),
                scan.step_run_id,
            ),
        )
        self.conn.commit()
        assert cur.lastrowid is not None
        scan.id = cur.lastrowid
        return scan

    def update(self, scan: Scan) -> None:
        self.conn.execute(
            "UPDATE scan SET status = ?, exit_code = ?, started_at = ?, finished_at = ?, "
            "command_str = ?, args_json = ?, raw_output_path = ?, artifact_path = ? "
            "WHERE id = ?;",
            (
                scan.status.value,
                scan.exit_code,
                _dt(scan.started_at),
                _dt(scan.finished_at),
                scan.command_str,
                json.dumps(scan.args),
                scan.raw_output_path,
                scan.artifact_path,
                scan.id,
            ),
        )
        self.conn.commit()


class HostRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def upsert(self, project_id: int, host: Host) -> int:
        self.conn.execute(
            "INSERT INTO host (project_id, ip, hostname, state, last_seen) "
            "VALUES (?, ?, ?, ?, datetime('now')) "
            "ON CONFLICT(project_id, ip) DO UPDATE SET "
            "  hostname = COALESCE(excluded.hostname, host.hostname), "
            "  state = excluded.state, last_seen = datetime('now');",
            (project_id, host.ip, host.hostname, host.state),
        )
        self.conn.commit()
        row = self.conn.execute(
            "SELECT id FROM host WHERE project_id = ? AND ip = ?;", (project_id, host.ip)
        ).fetchone()
        return int(row["id"])

    def list_for_project(self, project_id: int) -> list[Host]:
        rows = self.conn.execute(
            "SELECT * FROM host WHERE project_id = ? ORDER BY ip;", (project_id,)
        ).fetchall()
        return [
            Host(
                id=r["id"],
                project_id=r["project_id"],
                ip=r["ip"],
                hostname=r["hostname"],
                state=r["state"],
            )
            for r in rows
        ]


class PortRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def upsert(self, host_id: int, scan_id: int | None, port: Port) -> int:
        self.conn.execute(
            "INSERT INTO port (host_id, discovered_by_scan_id, number, protocol, state, reason) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(host_id, number, protocol) DO UPDATE SET "
            "  state = excluded.state, reason = excluded.reason, "
            "  discovered_by_scan_id = excluded.discovered_by_scan_id;",
            (host_id, scan_id, port.number, port.protocol, port.state, port.reason),
        )
        self.conn.commit()
        row = self.conn.execute(
            "SELECT id FROM port WHERE host_id = ? AND number = ? AND protocol = ?;",
            (host_id, port.number, port.protocol),
        ).fetchone()
        return int(row["id"])

    def list_for_host(self, host_id: int) -> list[Port]:
        rows = self.conn.execute(
            "SELECT * FROM port WHERE host_id = ? ORDER BY number;", (host_id,)
        ).fetchall()
        services = ServiceRepository(self.conn)
        return [
            Port(
                id=r["id"],
                host_id=r["host_id"],
                discovered_by_scan_id=r["discovered_by_scan_id"],
                number=r["number"],
                protocol=r["protocol"],
                state=r["state"],
                reason=r["reason"],
                service=services.get_for_port(r["id"]),
            )
            for r in rows
        ]


class ServiceRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def upsert(self, port_id: int, service: Service) -> None:
        # A port carries at most one service row; replace any existing.
        self.conn.execute("DELETE FROM service WHERE port_id = ?;", (port_id,))
        self.conn.execute(
            "INSERT INTO service (port_id, name, product, version, extrainfo, cpe) "
            "VALUES (?, ?, ?, ?, ?, ?);",
            (port_id, service.name, service.product, service.version,
             service.extrainfo, service.cpe),
        )
        self.conn.commit()

    def get_for_port(self, port_id: int) -> Service | None:
        row = self.conn.execute(
            "SELECT * FROM service WHERE port_id = ? LIMIT 1;", (port_id,)
        ).fetchone()
        if row is None:
            return None
        return Service(
            id=row["id"],
            port_id=row["port_id"],
            name=row["name"],
            product=row["product"],
            version=row["version"],
            extrainfo=row["extrainfo"],
            cpe=row["cpe"],
        )


class FindingRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def create(self, finding: Finding) -> int:
        cur = self.conn.execute(
            "INSERT INTO finding (project_id, host_id, scan_id, source_tool, severity, "
            "title, detail) VALUES (?, ?, ?, ?, ?, ?, ?);",
            (
                finding.project_id,
                finding.host_id,
                finding.scan_id,
                finding.source_tool,
                finding.severity.value,
                finding.title,
                finding.detail,
            ),
        )
        self.conn.commit()
        assert cur.lastrowid is not None
        return cur.lastrowid

    def list_for_project(self, project_id: int) -> list[Finding]:
        rows = self.conn.execute(
            "SELECT * FROM finding WHERE project_id = ? ORDER BY id;", (project_id,)
        ).fetchall()
        return [
            Finding(
                id=r["id"],
                project_id=r["project_id"],
                host_id=r["host_id"],
                scan_id=r["scan_id"],
                source_tool=r["source_tool"],
                severity=Severity(r["severity"]),
                title=r["title"],
                detail=r["detail"],
                created_at=r["created_at"],
            )
            for r in rows
        ]


def _dt(value: object) -> str | None:
    """Render a datetime (or None) as an ISO string for SQLite text storage."""
    return None if value is None else str(value)


