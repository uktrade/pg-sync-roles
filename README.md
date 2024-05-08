# pg-sync-roles [![PyPI package](https://img.shields.io/pypi/v/pg-sync-roles?label=PyPI%20package)](https://pypi.org/project/pg-sync-roles/) [![Test suite](https://img.shields.io/github/actions/workflow/status/uktrade/pg-sync-roles/test.yaml?label=Test%20suite)](https://github.com/uktrade/pg-sync-roles/actions/workflows/test.yaml) [![Code coverage](https://img.shields.io/codecov/c/github/uktrade/pg-sync-roles?label=Code%20coverage)](https://app.codecov.io/gh/uktrade/pg-sync-roles)

Python utility function to ensure that a PostgreSQL role has certain permissions or role memberships

> [!WARNING]  
> Work in progress. This README serves as a rough design spec.

## Features

- Transparently handles high numbers of permissions - avoiding "row is too big" errors.
- Locks where necessary - working around "tuple concurrently updated" or "tuple concurrently deleted" errors" that can happen when permission changes are performed concurrently.
- Optionally removes permissions from roles
- Handles database connect, schema usage, table select permissions, and role memberships - typically useful when using PostgreSQL as a data warehouse with a high number of users that need granular permissions.


## Installation

pg-sync-roles can be installed from PyPI using pip. psycopg2 or psycopg (Psycopg 3) must also be explicitly installed.

```bash
pip install pg-sync-roles psycopg
```


## Usage

To give a user CONNECT privileges on a database, as well as membership of role:

```python
from pg_sync_roles import DatabaseConnect, RoleMembership, sync_roles

# For example purposes, PostgreSQL can be run locally using this...
# docker run --rm -it -e POSTGRES_HOST_AUTH_METHOD=trust -p 5432:5432 postgres

# ... which should work with this engine
engine = sa.create_engine('postgresql+psycopg://postgres@127.0.0.1:5432/')

with engine.begin() as conn:
    sync_roles(
        conn,
        'my_user_name',
        grants=(
            DatabaseConnect('my_database_name'),
            RoleMembership('my_role_name'),
        ),
    )
```

A more complex example, where permissions and memberships are granted, but also any existing permissions not passed are revoked:

```python
from pg_sync_roles import (
    RoleMembership,
    SchemaUsage,
    SchemaOwnership,
    TableSelect,
    sync_roles,
)

engine = sa.create_engine('postgresql+psycopg://postgres@127.0.0.1:5432/')

with engine.begin() as conn:
    sync_roles(
        conn,
        'my_role_name',
        grants=(
            TableSelect('my_schema', 'my_table'),
            SchemaUsage('my_schema'),
            RoleMembership('my_other_role'),
            SchemaOwnership('my_other_schema', create_if_not_exists=True),
        ),
        # Revokes all table select, schema usage, and role memberships
        # that are not not passed via the grants parameter
        revokes=(
            TableSelect,
            SchemaUsage,
            RoleMembership,
        ),
    )
```


## Compatibility

pg-sync-roles aims to be compatible with a wide range of Python and other dependencies:

- Python >= 3.7.1 (tested on 3.7.1, 3.8.0, 3.9.0, 3.10.0, and 3.11.0)
- psycopg2 >= 2.9.2 and Psycopg 3 >= 3.1.4
- SQLAlchemy >= 1.4.24 (tested on 1.4.24 and 2.0.0)
- PostgreSQL >= 9.6 (tested on 9.6, 10.0, 11.0, 12.0, 13.0, 14.0, 15.0, and 16.0)

Note that SQLAlchemy < 2 does not support Psycopg 3, and for SQLAlchemy < 2 `future=True` must be passed to its create_engine function.

There are no plans to drop support for any of the above.
