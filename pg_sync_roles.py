from enum import Enum
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from uuid import uuid4
import logging

import sqlalchemy as sa

try:
    from psycopg2 import sql as sql2
except ImportError:
    sql2 = None

try:
    from psycopg import sql as sql3
except ImportError:
    sql3 = None

logger = logging.getLogger()

class Privilege(Enum):
    SELECT = 1
    INSERT = 2
    UPDATE = 3
    DELETE = 4
    TRUNCATE = 5
    REFERENCES = 6
    TRIGGER = 7
    CREATE = 8
    CONNECT = 9
    TEMPORARY = 10
    EXECUTE = 11
    USAGE = 12
    SET = 13
    ALTER_SYSTEM = 14


SELECT = Privilege.SELECT
INSERT = Privilege.INSERT
UPDATE = Privilege.UPDATE
DELETE = Privilege.DELETE
TRUNCATE = Privilege.TRUNCATE
REFERENCES = Privilege.REFERENCES
TRIGGER = Privilege.TRIGGER
CREATE = Privilege.CREATE
CONNECT = Privilege.CONNECT
TEMPORARY = Privilege.TEMPORARY
EXECUTE = Privilege.EXECUTE
USAGE = Privilege.USAGE
SET = Privilege.SET
ALTER_SYSTEM = Privilege.ALTER_SYSTEM


@dataclass(frozen=True)
class DatabaseConnect:
    database_name: str


@dataclass(frozen=True)
class SchemaUsage:
    schema_name: str


@dataclass(frozen=True)
class SchemaCreate:
    schema_name: str


@dataclass(frozen=True)
class SchemaOwnership:
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


def sync_roles(conn, role_name, grants=(), preserve_existing_grants_in_schemas=(), lock_key=1):
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

    @contextmanager
    def temporary_grant_of(role_names):
        # Expected to be called in a transaction context as above, so if an exception is thrown,
        # it will roll back. The REVOKE is _not_ in a finally: block because if there was an
        # this will then cause another error
        logger.info("Temporarily granting roles %s to CURRENT_USER", role_names)
        if role_names:
            execute_sql(sql.SQL('GRANT {role_names} TO CURRENT_USER').format(
                role_names=sql.SQL(',').join(sql.Identifier(role_name) for role_name, in role_names),
            ))
        yield
        logger.info("Revoking roles %s from CURRENT_USER", role_names)
        if role_names:
            execute_sql(sql.SQL('REVOKE {role_names} FROM CURRENT_USER').format(
                role_names=sql.SQL(',').join(sql.Identifier(role_name) for role_name, in role_names)
            ))

    def lock():
        execute_sql(sql.SQL("SELECT pg_advisory_xact_lock({lock_key})").format(lock_key=sql.Literal(lock_key)))

    def get_database_oid():
        return execute_sql(sql.SQL('''
            SELECT oid FROM pg_database WHERE datname = current_database()
        ''')).fetchall()[0][0]

    def get_role_exists(role_name):
        return execute_sql(sql.SQL("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = {role_name})").format(
            role_name=sql.Literal(role_name),
        )).fetchall()[0][0]

    def get_existing(table_name, column_name, values_to_search_for):
        if not values_to_search_for:
            return []
        return execute_sql(sql.SQL('SELECT {column_name} FROM {table_name} WHERE {column_name} IN ({values_to_search_for})').format(
            table_name=sql.Identifier(table_name),
            column_name=sql.Identifier(column_name),
            values_to_search_for=sql.SQL(',').join(
                sql.Literal(value) for value in values_to_search_for
            )
        )).fetchall()

    def get_existing_in_schema(table_name, namespace_column_name, row_name_column_name, values_to_search_for):
        if not values_to_search_for:
            return []
        return execute_sql(sql.SQL('''
            SELECT nspname, {row_name_column_name}
            FROM {table_name} c
            INNER JOIN pg_namespace n ON n.oid = c.{namespace_column_name}
            WHERE (nspname, {row_name_column_name}) IN ({values_to_search_for})
        ''').format(
            table_name=sql.Identifier(table_name),
            namespace_column_name=sql.Identifier(namespace_column_name),
            row_name_column_name=sql.Identifier(row_name_column_name),
            values_to_search_for=sql.SQL(',').join(
                sql.SQL('({},{})').format(sql.Literal(schema_name), sql.Literal(row_name))
                for (schema_name, row_name) in values_to_search_for
            )
        )).fetchall()

    def get_owners(table_name, owner_column_name, name_column_name, values_to_search_for):
        if not values_to_search_for:
            return []
        return execute_sql(sql.SQL('''
            SELECT DISTINCT rolname
            FROM {table_name}
            INNER JOIN pg_roles r ON r.oid = {owner_column_name}
            WHERE {name_column_name} IN ({values_to_search_for})
        ''').format(
            table_name=sql.Identifier(table_name),
            owner_column_name=sql.Identifier(owner_column_name),
            name_column_name=sql.Identifier(name_column_name),
            values_to_search_for=sql.SQL(',').join(
                sql.Literal(value) for value in values_to_search_for
            )
        )).fetchall()

    def get_owners_in_schema(table_name, owner_column_name, namespace_column_name, row_name_column_name, values_to_search_for):
        if not values_to_search_for:
            return []
        return execute_sql(sql.SQL('''
            SELECT DISTINCT rolname
            FROM {table_name} c
            INNER JOIN pg_namespace n ON n.oid = c.{namespace_column_name}
            INNER JOIN pg_roles r ON r.oid = {owner_column_name}
            WHERE (nspname, {row_name_column_name}) IN ({values_to_search_for})
        ''').format(
            table_name=sql.Identifier(table_name),
            owner_column_name=sql.Identifier(owner_column_name),
            namespace_column_name=sql.Identifier(namespace_column_name),
            row_name_column_name=sql.Identifier(row_name_column_name),
            values_to_search_for=sql.SQL(',').join(
                sql.SQL('({},{})').format(sql.Literal(schema_name), sql.Literal(row_name))
                for (schema_name, row_name) in values_to_search_for
            )
        )).fetchall()

    def get_acl_roles(privilege_type, table_name, row_name_column_name, acl_column_name, role_pattern, row_names):
        row_name_role_names = \
            [] if not row_names else \
            execute_sql(sql.SQL("""
                SELECT row_names.name, grantee::regrole
                FROM (
                    VALUES {row_names}
                ) row_names(name)
                LEFT JOIN (
                    SELECT {row_name_column_name}, grantee
                    FROM {table_name}, aclexplode({acl_column_name})
                    WHERE grantee::regrole::text LIKE {role_pattern}
                    AND privilege_type = {privilege_type}
                ) grantees ON grantees.{row_name_column_name} = row_names.name
            """).format(
                privilege_type=sql.Literal(privilege_type),
                table_name=sql.Identifier(table_name),
                row_name_column_name=sql.Identifier(row_name_column_name),
                acl_column_name=sql.Identifier(acl_column_name),
                role_pattern=sql.Literal(role_pattern),
                row_names=sql.SQL(',').join(
                    sql.SQL('({})').format(sql.Literal(row_name))
                    for row_name in row_names
                )
            )).fetchall()

        return {
            row_name: role_name
            for row_name, role_name in row_name_role_names
        }

    def get_acl_roles_in_schema(privilege_type, table_name, row_name_column_name, acl_column_name, namespace_oid_column_name, role_pattern, row_names):
        row_name_role_names = \
            [] if not table_selects else \
            execute_sql(sql.SQL("""
                SELECT all_names.schema_name, all_names.row_name, grantee::regrole
                FROM (
                    VALUES {row_names}
                ) all_names(schema_name, row_name)
                LEFT JOIN (
                    SELECT nspname AS schema_name, {row_name_column_name} AS row_name, grantee
                    FROM {table_name}
                    INNER JOIN pg_namespace ON pg_namespace.oid = pg_class.{namespace_oid_column_name}
                    CROSS JOIN aclexplode({acl_column_name})
                    WHERE grantee::regrole::text LIKE {role_pattern}
                    AND privilege_type = {privilege_type}
                ) grantees ON grantees.schema_name = all_names.schema_name AND grantees.row_name = all_names.row_name
            """).format(
                privilege_type=sql.Literal(privilege_type),
                table_name=sql.Identifier(table_name),
                row_name_column_name=sql.Identifier(row_name_column_name),
                acl_column_name=sql.Identifier(acl_column_name),
                namespace_oid_column_name=sql.Identifier(namespace_oid_column_name),
                role_pattern=sql.Literal(role_pattern),
                row_names=sql.SQL(',').join(
                    sql.SQL('({},{})').format(
                        sql.Literal(schema_name),
                        sql.Literal(row_name),
                    )
                    for (schema_name, row_name) in row_names
                )
            )).fetchall()

        return {
            (schema_name, row_name): role_name
            for schema_name, row_name, role_name in row_name_role_names
        }

    def get_existing_permissions(role_name, preserve_existing_grants_in_schemas):
        preserve_existing_grants_in_schemas_set = set(preserve_existing_grants_in_schemas)
        results = tuple(row._mapping for row in execute_sql(sql.SQL(_EXISTING_PERMISSIONS_SQL).format(
            role_name=sql.Literal(role_name)
        )).fetchall())
        return tuple(row for row in results if row['on'] not in _IN_SCHEMA or row['name_1'] not in preserve_existing_grants_in_schemas_set)

    def get_available_acl_role(base):
        for _ in range(0, 10):
            database_connect_role = base + uuid4().hex[:8]
            if not get_role_exists(database_connect_role):
                return database_connect_role

        raise RuntimeError('Unable to find available role name')

    def get_acl_rows(permissions, matching_on):
        return tuple(row for row in permissions if row['on'] in matching_on and row['privilege_type'] in _KNOWN_PRIVILEGES)

    def create_role(role_name):
        logger.info("Creating ROLE %s", role_name)
        execute_sql(sql.SQL('CREATE ROLE {role_name};').format(role_name=sql.Identifier(role_name)))

    def create_schema(schema_name):
        logger.info("Creating SCHEMA %s", schema_name)
        execute_sql(sql.SQL('CREATE SCHEMA {schema_name};').format(schema_name=sql.Identifier(schema_name)))

    def grant(grant_type, object_type, object_name, role_name):
        logger.info("Granting %s on %s %s to role %s", grant_type, object_type, object_name, role_name)
        execute_sql(sql.SQL('GRANT {grant_type} ON {object_type} {object_name} TO {role_name}').format(
            grant_type=grant_type,
            object_type=object_type,
            object_name=sql.Identifier(*object_name),
            role_name=sql.Identifier(role_name),
        ))

    def revoke(grant_type, object_type, object_name, role_name):
        logger.info("Revoking %s on %s %s to role %s", grant_type, object_type, object_name, role_name)
        execute_sql(sql.SQL('REVOKE {grant_type} ON {object_type} {object_name} FROM {role_name}').format(
            grant_type=grant_type,
            object_type=object_type,
            object_name=sql.Identifier(*object_name),
            role_name=sql.Identifier(role_name),
        ))

    def grant_ownership(object_type, role_name, object_name):
        logger.info("Granting schema ownership on %s %s to role %s", object_type, object_name, role_name)
        execute_sql(sql.SQL('ALTER {object_type} {object_name} OWNER TO {role_name}').format(
            object_type=object_type,
            role_name=sql.Identifier(role_name),
            object_name=sql.Identifier(object_name),
        ))

    def revoke_ownership(object_type, role_name, object_name):
        logger.info("Revoking schema ownership of %s %s from role %s", object_type, object_name, role_name)
        execute_sql(sql.SQL('ALTER {object_type} {object_name} OWNER TO CURRENT_USER').format(
            object_type=object_type,
            object_name=sql.Identifier(object_name),
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

    sql_grants = {
        SELECT: sql.SQL('SELECT'),
        INSERT: sql.SQL('INSERT'),
        UPDATE: sql.SQL('UPDATE'),
        DELETE: sql.SQL('DELETE'),
        TRUNCATE: sql.SQL('TRUNCATE'),
        REFERENCES: sql.SQL('REFERENCES'),
        TRIGGER: sql.SQL('TRIGGER'),
        CREATE: sql.SQL('CREATE'),
        CONNECT: sql.SQL('CONNECT'),
        TEMPORARY: sql.SQL('TEMPORARY'),
        EXECUTE: sql.SQL('EXECUTE'),
        USAGE: sql.SQL('USAGE'),
        SET: sql.SQL('SET'),
        ALTER_SYSTEM : sql.SQL('ALTER SYSTEM'),
    }

    sql_object_types = {
        TableSelect: sql.SQL('TABLE'),
        DatabaseConnect: sql.SQL('DATABASE'),
        SchemaUsage: sql.SQL('SCHEMA'),
        SchemaCreate: sql.SQL('SCHEMA'),
    }

    # Split grants by their type
    database_connects = tuple(grant for grant in grants if isinstance(grant, DatabaseConnect))
    schema_usages = tuple(grant for grant in grants if isinstance(grant, SchemaUsage))
    schema_creates = tuple(grant for grant in grants if isinstance(grant, SchemaCreate))
    schema_ownerships = tuple(grant for grant in grants if isinstance(grant, SchemaOwnership))
    table_selects = tuple(grant for grant in grants if isinstance(grant, TableSelect))
    logins = tuple(grant for grant in grants if isinstance(grant, Login))
    role_memberships = tuple(grant for grant in grants if isinstance(grant, RoleMembership))

    # Gather names of related grants (used for example to check if things exist)
    all_database_names = tuple(grant.database_name for grant in database_connects)
    all_schema_names = tuple(grant.schema_name for grant in grants if isinstance(grant, (SchemaUsage, SchemaCreate, SchemaOwnership)))
    all_table_names = tuple((grant.schema_name, grant.table_name) for grant in table_selects)

    # Validation
    if len(logins) > 1:
        raise ValueError('At most 1 Login object can be passed via the grants parameter')

    with transaction():
        # Get database OID that are in database-specific role names
        db_oid = get_database_oid()

        # Find existing objects where needed
        databases_that_exist = set(get_existing('pg_database', 'datname', all_database_names))
        schemas_that_exist = set(get_existing('pg_namespace', 'nspname', all_schema_names))
        tables_that_exist = set(get_existing_in_schema('pg_class', 'relnamespace', 'relname', all_table_names))

        # Filter out ACLs grants for databases, schemas and tables that don't exist
        database_connects = tuple(database_connect for database_connect in database_connects if (database_connect.database_name,) in databases_that_exist)
        schema_usages = tuple(schema_usage for schema_usage in schema_usages if (schema_usage.schema_name,) in schemas_that_exist)
        schema_creates = tuple(schema_create for schema_create in schema_creates if (schema_create.schema_name,) in schemas_that_exist)
        table_selects = tuple(table_select for table_select in table_selects if (table_select.schema_name, table_select.table_name) in tables_that_exist)
        all_database_connect_names = tuple(grant.database_name for grant in database_connects)
        all_schema_usage_names = tuple(grant.schema_name for grant in schema_usages)
        all_schema_create_names = tuple(grant.schema_name for grant in schema_creates)
        all_table_select_names = tuple((grant.schema_name, grant.table_name) for grant in table_selects)

        # Find if we need to make the role
        role_to_create = not get_role_exists(role_name)

        # Get all existing permissions
        existing_permissions = get_existing_permissions(role_name, preserve_existing_grants_in_schemas) if not role_to_create else []

        # Real ACL permissions - we revoke them all
        acl_table_permissions_to_revoke = get_acl_rows(existing_permissions, _TABLE_LIKE)
        acl_schema_permissions_to_revoke = get_acl_rows(existing_permissions, _SCHEMA)

        # And the ACL-equivalent roles
        database_connect_roles = get_acl_roles(
            'CONNECT', 'pg_database', 'datname', 'datacl', '\\_pgsr\\_global\\_database\\_connect\\_%',
            all_database_connect_names)
        database_connect_roles_to_create = keys_with_none_value(database_connect_roles)

        schema_usage_roles = get_acl_roles(
            'USAGE', 'pg_namespace', 'nspname', 'nspacl', f'\\_pgsr\\_local\\_{db_oid}_\\schema\\_usage\\_%',
            all_schema_usage_names)
        schema_usage_roles_to_create = keys_with_none_value(schema_usage_roles)

        schema_create_roles = get_acl_roles(
            'CREATE', 'pg_namespace', 'nspname', 'nspacl', f'\\_pgsr\\_local\\_{db_oid}_\\schema\\_create\\_%',
            all_schema_create_names)
        schema_create_roles_to_create = keys_with_none_value(schema_create_roles)

        table_select_roles = get_acl_roles_in_schema(
            'SELECT', 'pg_class', 'relname', 'relacl', 'relnamespace', f'\\_pgsr\\_local\\_{db_oid}_\\table\\_select\\_%',
            all_table_select_names)
        table_select_roles_to_create = keys_with_none_value(table_select_roles)

        # Ownerships to grant and revoke
        schema_ownerships_that_exist = tuple(SchemaOwnership(perm['name_1']) for perm in existing_permissions if perm['on'] == 'schema' and perm['privilege_type'] == 'OWNER')
        schema_ownerships_to_revoke = tuple(schema_ownership for schema_ownership in schema_ownerships_that_exist if schema_ownership not in schema_ownerships)
        schema_ownerships_to_grant = tuple(schema_ownership for schema_ownership in schema_ownerships if schema_ownership not in schema_ownerships_that_exist)

        # And any memberships of the database connect roles or explicitly requested role memberships
        memberships = set(perm['name_1'] for perm in existing_permissions if perm['on'] == 'role' and perm['privilege_type'] == 'MEMBER')
        database_connect_memberships_to_grant = tuple(role for role in database_connect_roles.values() if role not in memberships)
        schema_usage_memberships_to_grant = tuple(role for role in schema_usage_roles.values() if role not in memberships)
        schema_create_memberships_to_grant = tuple(role for role in schema_create_roles.values() if role not in memberships)
        table_select_memberships_to_grant = tuple(role for role in table_select_roles.values() if role not in memberships)
        role_memberships_to_grant = tuple(role_membership for role_membership in role_memberships if role_membership.role_name not in memberships)

        # And if the role can login / its login status is to be changed
        login_row = next((perm for perm in existing_permissions if perm['on'] == 'cluster' and perm['privilege_type'] == 'LOGIN'), None)
        can_login = login_row is not None

        valid_until = datetime.strptime(login_row['name_1'], '%Y-%m-%dT%H:%M:%S.%f%z') if login_row is not None else None
        logins_to_grant = logins and (not can_login or valid_until != logins[0].valid_until or logins[0].password is not None)
        logins_to_revoke = not logins and can_login

        # And any memberships to revoke
        memberships_to_revoke = memberships \
            - set(role_membership.role_name for role_membership in role_memberships) \
            - set(role for role in database_connect_roles.values()) \
            - set(role for role in table_select_roles.values()) \
            - set(role for role in schema_usage_roles.values()) \
            - set(role for role in schema_create_roles.values()) \

        # If we don't need to do anything, we're done.
        if (
            not role_to_create
            and not database_connect_roles_to_create
            and not schema_usage_roles_to_create
            and not schema_create_roles_to_create
            and not table_select_roles_to_create
            and not database_connect_memberships_to_grant
            and not schema_usage_memberships_to_grant
            and not table_select_memberships_to_grant
            and not role_memberships_to_grant
            and not memberships_to_revoke
            and not logins_to_grant
            and not logins_to_revoke
            and not schema_ownerships_to_revoke
            and not schema_ownerships_to_grant
            and not acl_table_permissions_to_revoke
            and not acl_schema_permissions_to_revoke
        ):
            return

        # But If we do need to make changes, lock, and then re-check everything
        lock()

        # Make the role if we need to
        role_to_create = not get_role_exists(role_name)
        if role_to_create:
            create_role(role_name)

        # The current user - if we need to change ownership or grant directly on an object
        # we need to check if the current use is the owner, and grant the owner to the user if not
        current_user = execute_sql(sql.SQL('SELECT CURRENT_USER')).fetchall()[0][0]

        # Find existing objects where needed
        databases_that_exist = set(get_existing('pg_database', 'datname', all_database_names))
        schemas_that_exist = set(get_existing('pg_namespace', 'nspname', all_schema_names))
        tables_that_exist = set(get_existing_in_schema('pg_class', 'relnamespace', 'relname', all_table_names))

        # Get all existing permissions
        existing_permissions = get_existing_permissions(role_name, preserve_existing_grants_in_schemas)

        # Gather all changes to be made to objects - the current user must be owner of them
        schema_ownerships_that_exist = tuple(SchemaOwnership(perm['name_1']) for perm in existing_permissions if perm['on'] == 'schema' and perm['privilege_type'] == 'OWNER')
        schema_ownerships_to_revoke = tuple(schema_ownership for schema_ownership in schema_ownerships_that_exist if schema_ownership not in schema_ownerships)
        schema_ownerships_to_grant = tuple(schema_ownership for schema_ownership in schema_ownerships if schema_ownership not in schema_ownerships_that_exist)
        database_connect_roles = get_acl_roles(
            'CONNECT', 'pg_database', 'datname', 'datacl', '\\_pgsr\\_global\\_database\\_connect\\_%',
            all_database_connect_names)
        database_connect_roles_to_create = keys_with_none_value(database_connect_roles)
        schema_usage_roles = get_acl_roles(
            'USAGE', 'pg_namespace', 'nspname', 'nspacl', f'\\_pgsr\\_local\\_{db_oid}_\\schema\\_usage\\_%',
            all_schema_usage_names)
        schema_usage_roles_to_create = keys_with_none_value(schema_usage_roles)
        schema_create_roles = get_acl_roles(
            'CREATE', 'pg_namespace', 'nspname', 'nspacl', f'\\_pgsr\\_local\\_{db_oid}_\\schema\\_create\\_%',
            all_schema_create_names)
        schema_create_roles_to_create = keys_with_none_value(schema_create_roles)
        table_select_roles = get_acl_roles_in_schema(
            'SELECT', 'pg_class', 'relname', 'relacl', 'relnamespace', f'\\_pgsr\\_local\\_{db_oid}_\\table\\_select\\_%',
            all_table_select_names)
        table_select_roles_to_create = keys_with_none_value(table_select_roles)
        acl_table_permissions_to_revoke = get_acl_rows(existing_permissions, _TABLE_LIKE)
        acl_schema_permissions_to_revoke = get_acl_rows(existing_permissions, _SCHEMA)

        # Find the roles that own all the objects to be manipulated
        # For each table, we also need USAGE on its schemas, but it's not guaranteed that the
        # current user would already have it. In most cases the owner of its schema would have usage
        # Maybe there's a more robust way that would cover more cases, but it would be more complicated
        databases_needing_ownerships = \
            database_connect_roles_to_create
        tables_needing_ownerships = \
            table_select_roles_to_create + \
            tuple((perm['name_1'], perm['name_2']) for perm in acl_table_permissions_to_revoke)
        schemas_needing_ownership = \
            tuple(schema_ownership.schema_name for schema_ownership in schema_ownerships_to_revoke) + \
            tuple(schema_ownership.schema_name for schema_ownership in schema_ownerships_to_grant) + \
            tuple(perm['name_1'] for perm in acl_schema_permissions_to_revoke) + \
            schema_usage_roles_to_create + \
            tuple(schema_name for schema_name, table_name in tables_needing_ownerships)

        # ... and temporarily grant the current user them
        database_owners = get_owners('pg_database', 'datdba', 'datname', databases_needing_ownerships)
        schema_owners = get_owners('pg_namespace', 'nspowner', 'nspname', schemas_needing_ownership)
        table_owners = get_owners_in_schema('pg_class', 'relowner', 'relnamespace', 'relname', tables_needing_ownerships)
        owners_to_grant = tuple(({(role_name,)} | set(database_owners) | set(schema_owners) | set(table_owners)) - {(current_user,)})
        with temporary_grant_of(owners_to_grant):

            # Grant or revoke schema ownerships
            for schema_ownership in schema_ownerships_to_revoke:
                revoke_ownership(sql_object_types[SchemaUsage], role_name, schema_ownership.schema_name)
            for schema_ownership in schema_ownerships_to_grant:
                if (schema_ownership.schema_name,) not in schemas_that_exist:
                    create_schema(schema_ownership.schema_name)
                grant_ownership(sql_object_types[SchemaUsage], role_name, schema_ownership.schema_name)

            # Create database connect roles if we need to
            for database_name in database_connect_roles_to_create:
                database_connect_role = get_available_acl_role('_pgsr_global_database_connect_')
                create_role(database_connect_role)
                grant(sql_grants[CONNECT], sql_object_types[DatabaseConnect], (database_name,), database_connect_role)
                database_connect_roles[database_name] = database_connect_role

            # Create schema usage roles if we need to
            for schema_name in schema_usage_roles_to_create:
                schema_usage_role = get_available_acl_role(f'_pgsr_local_{db_oid}_schema_usage_')
                create_role(schema_usage_role)
                grant(sql_grants[USAGE], sql_object_types[SchemaUsage], (schema_name,), schema_usage_role)
                schema_usage_roles[schema_name] = schema_usage_role

            # Create schema create roles if we need to
            for schema_name in schema_create_roles_to_create:
                schema_create_role = get_available_acl_role(f'_pgsr_local_{db_oid}_schema_create_')
                create_role(schema_create_role)
                grant(sql_grants[CREATE], sql_object_types[SchemaCreate], (schema_name,), schema_create_role)
                schema_create_roles[schema_name] = schema_create_role

            # Create table select roles if we need to
            for schema_name, table_name in table_select_roles_to_create:
                table_select_role = get_available_acl_role(f'_pgsr_local_{db_oid}_table_select_')
                create_role(table_select_role)
                grant(sql_grants[SELECT], sql_object_types[TableSelect], (schema_name, table_name), table_select_role)
                table_select_roles[(schema_name, table_name)] = table_select_role

            # Re-check existing permissions because granting ownership by default gives the owner full permissions
            existing_permissions = get_existing_permissions(role_name, preserve_existing_grants_in_schemas)
            acl_table_permissions_to_revoke = get_acl_rows(existing_permissions, _TABLE_LIKE)
            acl_schema_permissions_to_revoke = get_acl_rows(existing_permissions, _SCHEMA)

            # Revoke direct permissions on tables and schemas
            for perm in acl_table_permissions_to_revoke:
                revoke(sql_grants[Privilege[perm['privilege_type']]], sql.SQL('TABLE'), (perm['name_1'], perm['name_2']), role_name)
            for perm in acl_schema_permissions_to_revoke:
                revoke(sql_grants[Privilege[perm['privilege_type']]], sql.SQL('SCHEMA'), (perm['name_1'],), role_name)

        # Grant login if we need to
        login_row = next((perm for perm in existing_permissions if perm['on'] == 'cluster' and perm['privilege_type'] == 'LOGIN'), None)
        can_login = login_row is not None
        valid_until = datetime.strptime(login_row['name_1'], '%Y-%m-%dT%H:%M:%S.%f%z') if login_row is not None else None
        if logins_to_grant:
            grant_login(role_name, logins[0])
        logins_to_revoke = not logins and can_login
        if logins_to_revoke:
            revoke_login(role_name)

        # Grant memberships if we need to
        memberships = set(perm['name_1'] for perm in existing_permissions if perm['on'] == 'role' and perm['privilege_type'] == 'MEMBER')
        database_connect_memberships_to_grant = tuple(role for role in database_connect_roles.values() if role not in memberships)
        table_select_memberships_to_grant = tuple(role for role in table_select_roles.values() if role not in memberships)
        schema_usage_memberships_to_grant = tuple(role for role in schema_usage_roles.values() if role not in memberships)
        schema_create_memberships_to_grant = tuple(role for role in schema_create_roles.values() if role not in memberships)
        role_memberships_to_grant = tuple(role_membership for role_membership in role_memberships if role_membership.role_name not in memberships)
        for membership in role_memberships_to_grant:
            if not get_role_exists(membership.role_name):
                create_role(membership.role_name)
        grant_memberships(database_connect_memberships_to_grant \
            + schema_usage_memberships_to_grant \
            + schema_create_memberships_to_grant \
            + table_select_memberships_to_grant \
            + tuple(membership.role_name for membership in role_memberships),
        role_name)

        # Revoke memberships if we need to
        memberships_to_revoke = memberships \
            - set(role_membership.role_name for role_membership in role_memberships) \
            - set(role for role in database_connect_roles.values()) \
            - set(role for role in schema_usage_roles.values()) \
            - set(role for role in schema_create_roles.values()) \
            - set(role for role in table_select_roles.values())
        revoke_memberships(memberships_to_revoke, role_name)


_KNOWN_PRIVILEGES = {
    'SELECT',
    'INSERT',
    'UPDATE',
    'DELETE',
    'TRUNCATE',
    'REFERENCES',
    'TRIGGER',
    'CREATE',
    'CONNECT',
    'TEMPORARY',
    'EXECUTE',
    'USAGE',
    'SET',
    'ALTER SYSTEM',
}


_TABLE_LIKE = {
    'table',
    'view',
    'materialized view',
    'foreign table',
    'partitioned table',
    'sequence',
}

_SCHEMA = {
    'schema',
}


_IN_SCHEMA = {
    # Table-like things
    'table',
    'view',
    'materialized view',
    'foreign table',
    'partitioned table',
    'sequence',
    # Type-like things
    'base type',
    'composite type',
    'enum type',
    'pseudo type',
    'range type',
    'multirange type',
    'domain'
    # Function-like things
    'function',
    'procedure',
    'aggregate function',
    'window function',
}


# Suspect this is going to turn into very hefty SQL query that will essentially fetch all current
# permissions granted to the role. Hence not having it inline with the Python code, and it being
# a touch over-engineered for what it does right now
# Based on the queries at at https://stackoverflow.com/a/78466268/1319998
_EXISTING_PERMISSIONS_SQL = '''
-- Cluster permissions not "on" anything else
SELECT
  'cluster' AS on,
  CASE WHEN privilege_type = 'LOGIN' AND rolvaliduntil IS NOT NULL THEN to_char(rolvaliduntil AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US+00:00') END AS name_1,
  NULL AS name_2,
  NULL AS name_3,
  privilege_type
FROM pg_roles, unnest(
  CASE WHEN rolcanlogin THEN ARRAY['LOGIN'] ELSE ARRAY[]::text[] END
    || CASE WHEN rolsuper THEN ARRAY['SUPERUSER'] ELSE ARRAY[]::text[] END
    || CASE WHEN rolcreaterole THEN ARRAY['CREATE ROLE'] ELSE ARRAY[]::text[] END
    || CASE WHEN rolcreatedb THEN ARRAY['CREATE DATABASE'] ELSE ARRAY[]::text[] END
) AS p(privilege_type)
WHERE oid = quote_ident({role_name})::regrole

UNION ALL

-- Direct role memberships
SELECT 'role' AS on, groups.rolname AS name_1, NULL AS name_2, NULL AS name_3, 'MEMBER' AS privilege_type
FROM pg_auth_members mg
INNER JOIN pg_roles groups ON groups.oid = mg.roleid
INNER JOIN pg_roles members ON members.oid = mg.member
WHERE members.rolname = {role_name}

UNION ALL

-- ACL or owned-by dependencies of the role - global or in the currently connected database
(
  WITH owned_or_acl AS (
    SELECT
      refobjid,  -- The referenced object: the role in this case
      classid,   -- The pg_class oid that the dependant object is in
      objid,     -- The oid of the dependant object in the table specified by classid
      deptype,   -- The dependency type: o==is owner, and might have acl, a==has acl and not owner
      objsubid   -- The 1-indexed column index for table column permissions. 0 otherwise.
    FROM pg_shdepend
    WHERE refobjid = quote_ident({role_name})::regrole
    AND refclassid='pg_catalog.pg_authid'::regclass
    AND deptype IN ('a', 'o')
    AND (dbid = 0 OR dbid = (SELECT oid FROM pg_database WHERE datname = current_database()))
  ),

  relkind_mapping(relkind, type) AS (
    VALUES
      ('r', 'table'),
      ('v', 'view'),
      ('m', 'materialized view'),
      ('f', 'foreign table'),
      ('p', 'partitioned table'),
      ('S', 'sequence')
  )

  -- Schema ownership
  SELECT 'schema' AS on, nspname AS name_1, NULL AS name_2, NULL AS name_3, 'OWNER' AS privilege_type
  FROM pg_namespace n
  INNER JOIN owned_or_acl a ON a.objid = n.oid
  WHERE classid = 'pg_namespace'::regclass AND deptype = 'o'

  UNION ALL

  -- Schema privileges
  SELECT 'schema' AS on, nspname AS name_1, NULL AS name_2, NULL AS name_3, privilege_type
  FROM pg_namespace n
  INNER JOIN owned_or_acl a ON a.objid = n.oid
  CROSS JOIN aclexplode(COALESCE(n.nspacl, acldefault('n', n.nspowner)))
  WHERE classid = 'pg_namespace'::regclass AND grantee = refobjid

  UNION ALL

  -- Table(-like) privileges
  SELECT r.type AS on, nspname AS name_1, relname AS name_2, NULL AS name_3, privilege_type
  FROM pg_class c
  INNER JOIN pg_namespace n ON n.oid = c.relnamespace
  INNER JOIN owned_or_acl a ON a.objid = c.oid
  CROSS JOIN aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner)))
  INNER JOIN relkind_mapping r ON r.relkind = c.relkind
  WHERE classid = 'pg_class'::regclass AND grantee = refobjid AND objsubid = 0
)
'''
