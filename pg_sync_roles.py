from contextlib import contextmanager
from dataclasses import dataclass, is_dataclass
from datetime import datetime
from uuid import uuid4

import sqlalchemy as sa

try:
    from psycopg2 import sql as sql2
except ImportError:
    sql2 = None

try:
    from psycopg import sql as sql3
except ImportError:
    sql3 = None


@dataclass(frozen=True)
class DatabaseConnect:
    database_name: str


@dataclass(frozen=True)
class Login:
    valid_until: datetime = None
    password: str = None


def sync_roles(conn, role_name, grants=(), lock_key=1):
    def execute_sql(sql_obj):
        return conn.execute(sa.text(sql_obj.as_string(conn.connection.driver_connection)))

    @contextmanager
    def transaction():
        try:
            conn.begin()
            yield
        except Exception:
            conn.rollback()
            raise
        else:
            conn.commit()

    def lock():
        execute_sql(sql.SQL("SELECT pg_advisory_xact_lock({lock_key})").format(lock_key=sql.Literal(lock_key)))

    def get_role_exists(role_name):
        return execute_sql(sql.SQL("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = {role_name})").format(
            role_name=sql.Literal(role_name),
        )).fetchall()[0][0]

    def get_database_connect_roles(database_connects):
        database_name_role_names = \
            [] if not database_connects else \
            execute_sql(sql.SQL("""
                SELECT database_name, grantee::regrole
                FROM (
                    VALUES {database_names}
                ) dn(database_name)
                LEFT JOIN (
                    SELECT datname, grantee
                    FROM pg_database, aclexplode(datacl)
                    WHERE grantee::regrole::text LIKE '\\_pgsr\\_database\\_connect\\_%'
                    AND privilege_type = 'CONNECT'
                ) grantees ON grantees.datname = dn.database_name
            """).format(database_names=sql.SQL(',').join(
                sql.SQL('({})').format(sql.Literal(database_connect.database_name))
                for database_connect in database_connects
            ))).fetchall()

        return {
            database_name: role_name
            for database_name, role_name in database_name_role_names
        }

    def get_memberships(role_name):
        membership_rows = execute_sql(sql.SQL('SELECT roleid::regrole FROM pg_auth_members WHERE member={role_name}::regrole').format(
            role_name=sql.Literal(role_name)
        )).fetchall()
        return tuple(membership for membership, in membership_rows)

    def create_role(role_name):
        execute_sql(sql.SQL('CREATE ROLE {role_name};').format(role_name=sql.Identifier(role_name)))

    def get_can_login_valid_until(role_name):
        return execute_sql(sql.SQL('''
            SELECT rolcanlogin, rolvaliduntil FROM pg_roles WHERE rolname={role_name} LIMIT 1'''
        ).format(role_name=sql.Literal(role_name))).fetchall()[0]

    def get_available_database_connect_role():
        for _ in range(0, 10):
            database_connect_role = '_pgsr_database_connect_' + uuid4().hex[:8]
            if not get_role_exists(database_connect_role):
                return database_connect_role

        raise Exception('Unable to find available role name')

    def grant_connect(database_name, role_name):
        execute_sql(sql.SQL('GRANT CONNECT ON DATABASE {database_name} TO {role_name}').format(
            database_name=sql.Identifier(database_name),
            role_name=sql.Identifier(role_name),
        ))

    def grant_login(role_name, login):
        execute_sql(sql.SQL('ALTER ROLE {role_name} WITH LOGIN PASSWORD {password} VALID UNTIL {valid_until}').format(
            role_name=sql.Identifier(role_name),
            password=sql.Literal(login.password),
            valid_until=sql.Literal(login.valid_until.isoformat()),
        ))

    def grant_memberships(memberships, role_name):
        if not memberships:
            return
        execute_sql(sql.SQL('GRANT {memberships} TO {role_name}').format(
            memberships=sql.SQL(',').join(sql.Identifier(membership) for membership in memberships),
            role_name=sql.Identifier(role_name),
        ))

    def keys_with_none_value(d):
        return tuple(key for key, value in d.items() if value is None)

    # Choose the correct library for dynamically constructing SQL based on the underlying
    # engine of the SQLAlchemy connection
    sql = {
        'psycopg2': sql2,
        'psycopg': sql3,
    }[conn.engine.driver]

    # Split grants by their type
    database_connects = tuple(grant for grant in grants if isinstance(grant, DatabaseConnect))
    logins = tuple(grant for grant in grants if isinstance(grant, Login))

    # Validation
    if len(logins) > 1:
        raise ValueError('At most 1 Login object can be passed via the grants parameter')

    with transaction():
        # Find if we need to make the role
        role_needed = not get_role_exists(role_name)

        # Or the database connect roles
        database_connect_roles = get_database_connect_roles(database_connects)
        database_connect_roles_needed = keys_with_none_value(database_connect_roles)

        # Or any memberships of the database connect roles
        memberships = set(get_memberships(role_name)) if not role_needed else set()
        memberships_needed = tuple(role for role in database_connect_roles.values() if role not in memberships)

        can_login, valid_until = get_can_login_valid_until(role_name) if not role_needed else (False, None)
        logins_needed = logins and (not can_login or valid_until != logins[0].valid_until or logins[0].password is not None)

        # If we don't need to do anything, we're done.
        if not role_needed and not database_connect_roles_needed and not memberships_needed and not logins_needed:
            return

        # But If we do need to make changes, lock, and then re-check everything
        lock()

        # Make the role if we need to
        role_needed = not get_role_exists(role_name)
        if role_needed:
            create_role(role_name)

        # Create database connect roles if we need to
        database_connect_roles = get_database_connect_roles(database_connects)
        database_connect_roles_needed = keys_with_none_value(database_connect_roles)
        for database_name in database_connect_roles_needed:
            database_connect_role = get_available_database_connect_role()
            create_role(database_connect_role)
            grant_connect(database_name, database_connect_role)
            database_connect_roles[database_name] = database_connect_role

        can_login, valid_until = get_can_login_valid_until(role_name)
        logins_needed = logins and (not can_login or valid_until != logins[0].valid_until or logins[0].password is not None)
        if logins_needed:
            grant_login(role_name, logins[0])

        # Grant memberships if we need to
        memberships = set(get_memberships(role_name)) if not role_needed else set()
        memberships_needed = tuple(role for role in database_connect_roles.values() if role not in memberships)
        grant_memberships(memberships_needed, role_name)
