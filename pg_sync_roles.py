from contextlib import contextmanager
from dataclasses import dataclass, is_dataclass
from datetime import datetime
from uuid import uuid4
import logging
logger = logging.getLogger()
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
class SchemaUsage:
    schema_name: str


@dataclass(frozen=True)
class TableSelect:
    schema_name: str
    table_name: str


@dataclass(frozen=True)
class Login:
    valid_until: datetime = None
    password: str = None


@dataclass(frozen=True)
class RoleMembership:
    role_name: str


def sync_roles(conn, role_name, grants=(), lock_key=1):
    def execute_sql(sql_obj):
        # This avoids "argument 1 must be psycopg2.extensions.connection, not PGConnectionProxy"
        # which can happen when elastic-apm wraps the connection object when using psycopg2
        unwrapped_connection = getattr(conn.connection.driver_connection, '__wrapped__', conn.connection.driver_connection)
        return conn.execute(sa.text(sql_obj.as_string(unwrapped_connection)))

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

    def get_databases_that_exist(database_connects):
        if not database_connects:
            return []
        return execute_sql(sql.SQL('SELECT datname FROM pg_database WHERE datname IN ({databases})').format(
            databases=sql.SQL(',').join(
                sql.Literal(database_connect.database_name) for database_connect in database_connects
            )
        )).fetchall()

    def get_database_oid():
        return execute_sql(sql.SQL('''
            SELECT oid FROM pg_database WHERE datname = current_database()
        ''')).fetchall()[0][0]

    def get_schemas_that_exist(schema_usages):
        if not schema_usages:
            return []
        return execute_sql(sql.SQL('SELECT nspname FROM pg_namespace WHERE nspname IN ({schemas})').format(
            schemas=sql.SQL(',').join(
                sql.Literal(schema_usage.schema_name) for schema_usage in schema_usages
            )
        )).fetchall()

    def get_tables_that_exist(table_selects):
        if not table_selects:
            return []
        return execute_sql(sql.SQL('''
            SELECT nspname, relname
            FROM pg_class c
            INNER JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE (nspname, relname) IN ({tables})
        ''').format(
            tables=sql.SQL(',').join(
                sql.SQL('({},{})').format(sql.Literal(table_select.schema_name), sql.Literal(table_select.table_name))
                for table_select in table_selects
            )
        )).fetchall()

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
                    WHERE grantee::regrole::text LIKE '\\_pgsr\\_global\\_database\\_connect\\_%'
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

    def get_schema_usage_roles(db_oid, schema_usages):
        schema_name_role_names = \
            [] if not schema_usages else \
            execute_sql(sql.SQL("""
                SELECT schema_name, grantee::regrole
                FROM (
                    VALUES {schema_names}
                ) sc(schema_name)
                LEFT JOIN (
                    SELECT nspname, grantee
                    FROM pg_namespace, aclexplode(nspacl)
                    WHERE grantee::regrole::text LIKE {role_pattern}
                    AND privilege_type = 'USAGE'
                ) grantees ON grantees.nspname = sc.schema_name
            """).format(
                role_pattern=sql.Literal(f'\\_pgsr\\_local\\_{db_oid}_\\_schema\\_usage\\_%'),
                schema_names=sql.SQL(',').join(
                    sql.SQL('({})').format(sql.Literal(schema_usage.schema_name))
                    for schema_usage in schema_usages
                ))
        ).fetchall()

        return {
            schema_name: role_name
            for schema_name, role_name in schema_name_role_names
        }

    def get_table_select_roles(db_oid, table_selects):
        tables_role_names = \
            [] if not table_selects else \
            execute_sql(sql.SQL("""
                SELECT tb.schema_name, tb.table_name, grantee::regrole
                FROM (
                    VALUES {tables}
                ) tb(schema_name, table_name)
                LEFT JOIN (
                    SELECT nspname AS schema_name, relname AS table_name, grantee
                    FROM pg_class
                    INNER JOIN pg_namespace ON pg_namespace.oid = pg_namespace.oid
                    CROSS JOIN aclexplode(relacl)
                    WHERE grantee::regrole::text LIKE {role_pattern}
                    AND privilege_type = 'SELECT'
                ) grantees ON grantees.schema_name = tb.schema_name AND grantees.table_name = tb.table_name
            """).format(
                role_pattern=sql.Literal(f'\\_pgsr\\_local\\_{db_oid}_\\_table\\_select\\_%'),
                tables=sql.SQL(',').join(
                    sql.SQL('({},{})').format(
                        sql.Literal(table_select.schema_name),
                        sql.Literal(table_select.table_name),
                    )
                    for table_select in table_selects
                ))
        ).fetchall()

        return {
            (schema_name, table_name): role_name
            for schema_name, table_name, role_name in tables_role_names
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

    def get_available_acl_role(base):
        for _ in range(0, 10):
            database_connect_role = base + uuid4().hex[:8]
            if not get_role_exists(database_connect_role):
                return database_connect_role

        raise RuntimeError('Unable to find available role name')

    def grant_connect(database_name, role_name):
        logger.info("Granting CONNECT on database %s to role %s", database_name, role_name)
        execute_sql(sql.SQL('GRANT CONNECT ON DATABASE {database_name} TO {role_name}').format(
            database_name=sql.Identifier(database_name),
            role_name=sql.Identifier(role_name),
        ))

    def grant_usage(schema_name, role_name):
        logger.info("Granting USAGE on schema %s to role %s", schema_name, role_name)
        execute_sql(sql.SQL('GRANT USAGE ON SCHEMA {schema_name} TO {role_name}').format(
            schema_name=sql.Identifier(schema_name),
            role_name=sql.Identifier(role_name),
        ))

    def grant_select(schema_name, table_name, role_name):
        logger.info("Granting SELECT on table %s to role %s", table_name, role_name)
        execute_sql(sql.SQL('GRANT SELECT ON TABLE {schema_name}.{table_name} TO {role_name}').format(
            schema_name=sql.Identifier(schema_name),
            table_name=sql.Identifier(table_name),
            role_name=sql.Identifier(role_name),
        ))

    def grant_login(role_name, login):
        logger.info("Granting LOGIN on login %s to role %s", login, role_name)
        execute_sql(sql.SQL('ALTER ROLE {role_name} WITH LOGIN PASSWORD {password} VALID UNTIL {valid_until}').format(
            role_name=sql.Identifier(role_name),
            password=sql.Literal(login.password),
            valid_until=sql.Literal(login.valid_until.isoformat()),
        ))

    def revoke_login(role_name):
        logger.info("Revoking LOGIN from role %s", role_name)
        execute_sql(sql.SQL('ALTER ROLE {role_name} WITH NOLOGIN PASSWORD NULL').format(
            role_name=sql.Identifier(role_name),
        ))

    def grant_memberships(memberships, role_name):
        if not memberships:
            logger.info("No memberships granted to %s", role_name)
            return
        logger.info("Granting memberships %s to role %s", memberships, role_name)
        execute_sql(sql.SQL('GRANT {memberships} TO {role_name}').format(
            memberships=sql.SQL(',').join(sql.Identifier(membership) for membership in memberships),
            role_name=sql.Identifier(role_name),
        ))

    def revoke_memberships(memberships, role_name):
        if not memberships:
            logger.info("No memberships revoked from %s", role_name)
            return
        logger.info("Revoking memberships %s from role %s", memberships, role_name)
        execute_sql(sql.SQL('REVOKE {memberships} FROM {role_name}').format(
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
    schema_usages = tuple(grant for grant in grants if isinstance(grant, SchemaUsage))
    table_selects = tuple(grant for grant in grants if isinstance(grant, TableSelect))
    logins = tuple(grant for grant in grants if isinstance(grant, Login))
    role_memberships = tuple(grant for grant in grants if isinstance(grant, RoleMembership))

    # Validation
    if len(logins) > 1:
        raise ValueError('At most 1 Login object can be passed via the grants parameter')

    with transaction():
        # Get database OID that are in database-specific role names
        db_oid = get_database_oid()

        # Filter out databases and tables that don't exist
        databases_that_exist = set(get_databases_that_exist(database_connects))
        database_connects = tuple(database_connect for database_connect in database_connects if (database_connect.database_name,) in databases_that_exist)
        schemas_that_exist = set(get_schemas_that_exist(schema_usages))
        schema_usages = tuple(schema_usage for schema_usage in schema_usages if (schema_usage.schema_name,) in schemas_that_exist)
        tables_that_exist = set(get_tables_that_exist(table_selects))
        table_selects = tuple(table_select for table_select in table_selects if (table_select.schema_name, table_select.table_name) in tables_that_exist)

        # Find if we need to make the role
        role_needed = not get_role_exists(role_name)

        # And the ACL-equivalent roles
        database_connect_roles = get_database_connect_roles(database_connects)
        database_connect_roles_needed = keys_with_none_value(database_connect_roles)
        schema_usage_roles = get_schema_usage_roles(db_oid, schema_usages)
        schema_usage_roles_needed = keys_with_none_value(schema_usage_roles)
        table_select_roles = get_table_select_roles(db_oid, table_selects)
        table_select_roles_needed = keys_with_none_value(table_select_roles)

        # And any memberships of the database connect roles or explicitly requested role memberships
        memberships = set(get_memberships(role_name)) if not role_needed else set()
        database_connect_memberships_needed = tuple(role for role in database_connect_roles.values() if role not in memberships)
        schema_usage_memberships_needed = tuple(role for role in schema_usage_roles.values() if role not in memberships)
        table_select_memberships_needed = tuple(role for role in table_select_roles.values() if role not in memberships)
        role_memberships_needed = tuple(role_membership for role_membership in role_memberships if role_membership.role_name not in memberships)

        # And if the role can login / its login status is to be changed
        can_login, valid_until = get_can_login_valid_until(role_name) if not role_needed else (False, None)
        logins_needed = logins and (not can_login or valid_until != logins[0].valid_until or logins[0].password is not None)
        logins_to_revoke = not logins and can_login

        # And any memberships to revoke
        memberships_to_revoke = memberships \
            - set(role_membership.role_name for role_membership in role_memberships) \
            - set(role for role in database_connect_roles.values()) \
            - set(role for role in table_select_roles.values())

        # If we don't need to do anything, we're done.
        if (
            not role_needed
            and not database_connect_roles_needed
            and not schema_usage_roles_needed
            and not table_select_roles_needed
            and not database_connect_memberships_needed
            and not schema_usage_memberships_needed
            and not table_select_memberships_needed
            and not role_memberships_needed
            and not memberships_to_revoke
            and not logins_needed
            and not logins_to_revoke
        ):
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
            database_connect_role = get_available_acl_role('_pgsr_global_database_connect_')
            create_role(database_connect_role)
            grant_connect(database_name, database_connect_role)
            database_connect_roles[database_name] = database_connect_role

        # Create schema usage roles if we need to
        schema_usage_roles = get_schema_usage_roles(db_oid, schema_usages)
        schema_usage_roles_needed = keys_with_none_value(schema_usage_roles)
        for schema_name in schema_usage_roles_needed:
            schema_usage_role = get_available_acl_role(f'_pgsr_local_{db_oid}_schema_usage_')
            create_role(schema_usage_role)
            grant_usage(schema_name, schema_usage_role)
            schema_usage_roles[schema_name] = schema_usage_role

        # Create table select roles if we need to
        table_select_roles = get_table_select_roles(db_oid, table_selects)
        table_select_roles_needed = keys_with_none_value(table_select_roles)
        for schema_name, table_name in table_select_roles_needed:
            table_select_role = get_available_acl_role(f'_pgsr_local_{db_oid}_table_select_')
            create_role(table_select_role)
            grant_select(schema_name, table_name, table_select_role)
            table_select_roles[(schema_name, table_name)] = table_select_role

        # Grant login if we need to
        can_login, valid_until = get_can_login_valid_until(role_name)
        logins_needed = logins and (not can_login or valid_until != logins[0].valid_until or logins[0].password is not None)
        if logins_needed:
            grant_login(role_name, logins[0])
        logins_to_revoke = not logins and can_login
        if logins_to_revoke:
            revoke_login(role_name)

        # Grant memberships if we need to
        memberships = set(get_memberships(role_name)) if not role_needed else set()
        database_connect_memberships_needed = tuple(role for role in database_connect_roles.values() if role not in memberships)
        table_select_memberships_needed = tuple(role for role in table_select_roles.values() if role not in memberships)
        schema_usage_memberships_needed = tuple(role for role in schema_usage_roles.values() if role not in memberships)
        role_memberships_needed = tuple(role_membership for role_membership in role_memberships if role_membership.role_name not in memberships)
        for membership in role_memberships_needed:
            if not get_role_exists(membership.role_name):
                create_role(membership.role_name)
        grant_memberships(database_connect_memberships_needed \
            + schema_usage_memberships_needed \
            + table_select_memberships_needed \
            + tuple(membership.role_name for membership in role_memberships),
        role_name)

        # Revoke memberships if we need to
        memberships_to_revoke = memberships \
            - set(role_membership.role_name for role_membership in role_memberships) \
            - set(role for role in database_connect_roles.values()) \
            - set(role for role in schema_usage_roles.values()) \
            - set(role for role in table_select_roles.values())
        revoke_memberships(memberships_to_revoke, role_name)
