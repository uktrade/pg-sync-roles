# pg-sync-roles

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
from pg_sync_roles import DatabaseConnect, RoleMembership, pg_sync_roles

# For example purposes, PostgreSQL can be run locally using this...
# docker run --rm -it -e POSTGRES_HOST_AUTH_METHOD=trust -p 5432:5432 postgres

# ... which should work with this engine
engine = sa.create_engine('postgresql+psycopg://postgres@127.0.0.1:5432/')

with engine.begin() as conn:
    pg_sync_roles(
        conn,
        'my_user_name',
        grants=(
            DatabaseConnect('my_database_name'),
            RoleMembership('my_role_name'),
        ),
    )
