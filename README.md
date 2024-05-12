# pg-sync-roles [![PyPI package](https://img.shields.io/pypi/v/pg-sync-roles?label=PyPI%20package)](https://pypi.org/project/pg-sync-roles/) [![Test suite](https://img.shields.io/github/actions/workflow/status/uktrade/pg-sync-roles/test.yaml?label=Test%20suite)](https://github.com/uktrade/pg-sync-roles/actions/workflows/test.yaml) [![Code coverage](https://img.shields.io/codecov/c/github/uktrade/pg-sync-roles?label=Code%20coverage)](https://app.codecov.io/gh/uktrade/pg-sync-roles)

Python utility function to ensure that a PostgreSQL role has certain permissions or role memberships

> [!WARNING]  
> Work in progress. This README serves as a rough design spec.

## Features

- Transparently handles high numbers of permissions - avoiding "row is too big" errors.
- Locks where necessary - working around "tuple concurrently updated" or "tuple concurrently deleted" errors that can happen when permission changes are performed concurrently.
- Automatically revokes permissions from roles not explicitly granted.
- Handles database connect, schema usage, table select permissions, and role memberships - typically useful when using PostgreSQL as a data warehouse with a high number of users that need granular permissions.


## Installation

pg-sync-roles can be installed from PyPI using pip. psycopg2 or psycopg (Psycopg 3) must also be explicitly installed.

```bash
pip install pg-sync-roles psycopg
```


## Usage

To give a user CONNECT on a database, as well as membership of role:

```python
from pg_sync_roles import Login, DatabaseConnect, RoleMembership, sync_roles

# For example purposes, PostgreSQL can be run locally using this...
# docker run --rm -it -e POSTGRES_HOST_AUTH_METHOD=trust -p 5432:5432 postgres

# ... which should work with this engine
engine = sa.create_engine('postgresql+psycopg://postgres@127.0.0.1:5432/')

with engine.connect() as conn:
    sync_roles(
        conn,
        'my_user_name',
        grants=(
            Login(password='...', valid_until='...'),
            DatabaseConnect('my_database_name'),
            RoleMembership('my_role_name'),
        ),
    )
```

Or to give a use SELECT on a table, USAGE on a schema, membersip of a role, and ownership of a schema:

```python
from pg_sync_roles import (
    RoleMembership,
    SchemaUsage,
    SchemaOwnership,
    TableSelect,
    sync_roles,
)

engine = sa.create_engine('postgresql+psycopg://postgres@127.0.0.1:5432/')

with engine.connect() as conn:
    sync_roles(
        conn,
        'my_role_name',
        grants=(
            TableSelect('my_schema', 'my_table'),
            SchemaUsage('my_schema'),
            RoleMembership('my_other_role'),
            SchemaOwnership('my_other_schema'),
        ),
    )
```


## Locking and coordination with other processes that manage permissions

pg-sync-roles obtains an advisory exclusive lock before making any changes - this avoids "tuple concurrently updated" or "tuple concurrently deleted" errors that can be raised when multiple connections change or delete the same permissions-related rows. It does this by calling the `pg_advisory_xact_lock(key bigint)` function. By default a key of 1 is used, but this can be changed by passing a different integer key as the `lock_key` parameter to `sync_roles`.

If you have other processes changing permissions outide of the `sync_roles` function, they should first obtain the same lock by explicitly calling `pg_advisory_xact_lock(key bigint)` with the same key.

The advisory lock is only obtained if `sync_roles` detects there are changes to be made, and is released by the time it returns.


## Under the hood

pg-sync-roles maintains a role per database perimission, a role per schema pemission, and a role per table permission. Rather than roles being granted permissions directly on objects, membership is granted to these roles that indirectly grant permissions on objects. This means that from the object's point of view, only 1 role has any given permission. This works around the de-facto limit on the number of roles that can have permission to any object.

The names of the roles maintained by pg-sync-roles begin with the prefix `_pgsr_`. Each name ends with a randomly generated unique identifier.


## What's revoked

pg-sync-roles tries to be exhaustive when revoking all privileges that aren't asked for. But note that roles are shared over a cluster, and not specific to a single database in a cluster, and so pg-sync-roles will only revoke privileges on shared objects, or those that are in the currently connected database.

In more detail, the `sync_roles` function will revoke:

- The ability to login, create roles, create databases, or being a superuser - these are stored with the role and so shared over the cluster.

- Membership of other roles - these are also shared over a cluster.

- Ownerships of and grants on databases, tablespaces, and parameters - these also shared over a cluster.

- Only on the current database: ownerships of and grants on schemas, tables (including the table-like views, materialized views, partitioned tables and foreign tables), table(-like) columns, sequences, functions, procedures, large objects, types (base, composite, enum, pseudo, range and multirange), domains, languages, foreign-data wrappers, and foreign servers.

  If you wish to revoke privileges on other databases, you will have connect to each database in turn and call `sync_roles` passing its connection.


## Compatibility

pg-sync-roles aims to be compatible with a wide range of Python and other dependencies:

- Python >= 3.7.1 (tested on 3.7.1, 3.8.0, 3.9.0, 3.10.0, and 3.11.0)
- psycopg2 >= 2.9.2 (tested on 3.9.2) and Psycopg 3 >= 3.1.4 (tested on 3.1.4)
- SQLAlchemy >= 1.4.24 (tested on 1.4.24 and 2.0.0)
- PostgreSQL >= 9.6 (tested on 9.6, 10.0, 11.0, 12.0, 13.0, 14.0, 15.0, and 16.0)

Note that SQLAlchemy < 2 does not support Psycopg 3, and for SQLAlchemy < 2 `future=True` must be passed to its create_engine function.

There are no plans to drop support for any of the above.
