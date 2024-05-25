# pg-sync-roles [![PyPI package](https://img.shields.io/pypi/v/pg-sync-roles?label=PyPI%20package)](https://pypi.org/project/pg-sync-roles/) [![Test suite](https://img.shields.io/github/actions/workflow/status/uktrade/pg-sync-roles/test.yaml?label=Test%20suite)](https://github.com/uktrade/pg-sync-roles/actions/workflows/test.yaml) [![Code coverage](https://img.shields.io/codecov/c/github/uktrade/pg-sync-roles?label=Code%20coverage)](https://app.codecov.io/gh/uktrade/pg-sync-roles)

Python utility function to ensure that a PostgreSQL role has certain permissions or role memberships, and no others. While pg-sync-roles removes the need of a lot of the boilerplate in order to manage permissions, it is a light abstraction layer over the PostgreSQL permission system. Therefore to use pg-sync-roles effectively and securely, you should have knowledge of:

- [PostgreSQL privileges](https://www.postgresql.org/docs/current/ddl-priv.html)
- [PostgreSQL role attributes](https://www.postgresql.org/docs/current/role-attributes.html)
- [PostgreSQL database roles](https://www.postgresql.org/docs/current/user-manag.html)

pg-sync-roles should not be used on roles that should have permissions to multiple database in a cluster (although this limitation may be removed in future versions).

---

### Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [API](#api)
- [Locking](#locking)
- [Under the hood](#under-the-hood)
- [Compatibility](#compatibility)
- [Running tests locally](#running-tests-locally)
- [Design decisions](#design-decisions)

---

## Features

- Transparently handles high numbers of permissions - avoiding "row is too big" errors.
- Locks where necessary - working around "tuple concurrently updated" or "tuple concurrently deleted" errors that can happen when permission changes are performed concurrently.
- Does _not_ require the connecting user to be SUPERUSER
- Can grant (and so automatically revokes if not requested):
  -  Login (with password and expiry)
  -  Role memberships
  -  Database CONNECT
  -  Schema USAGE, CREATE, and ownership
  -  Table (and table-like) SELECT
- Also automatically revokes all non-SELECT permissions on table-like objects, for example INSERT.
- Allows for contents of specific schemas to be ignored for the purposes of management of permissions
 
 These features make pg-sync-roles useful when using PostgreSQL as a data warehouse with a high number of users that need granular permissions. The lack of SUPERUSER requirement means that pg-sync-roles is suitable for managed PostgreSQL clusters, for example in Amazon RDS.
 
 Other types of privileges and other object types may be added in future versions.

> [!IMPORTANT]  
> pg-sync-roles does not revoke any permissions granted to the PUBLIC pseudo-role


## Installation

pg-sync-roles can be installed from PyPI using pip. psycopg2 or psycopg (Psycopg 3) must also be explicitly installed.

```bash
pip install pg-sync-roles psycopg
```


## Usage

To give a role the ability to login (with a random password valid for 28 days), CONNECT to a database, and membership of another role:

```python
import string
import secrets
from datetime import datetime, timedelta, timezone
from pg_sync_roles import Login, DatabaseConnect, RoleMembership, sync_roles

# For example purposes, PostgreSQL can be run locally using this...
# docker run --rm -it -e POSTGRES_HOST_AUTH_METHOD=trust -p 5432:5432 postgres

# ... which should work with this engine
engine = sa.create_engine('postgresql+psycopg://postgres@127.0.0.1:5432/')

password_alphabet = string.ascii_letters + string.digits
password = ''.join(secrets.choice(password_alphabet) for i in range(64))

valid_until = datetime.now(timezone.utc) + timedelta(days=28)

with engine.connect() as conn:
    sync_roles(
        conn,
        'my_user_name',
        grants=(
            Login(password=password, valid_until=valid_until),
            DatabaseConnect('my_database_name'),
            RoleMembership('my_role_name'),
        ),
    )
```

Or to give a role SELECT on a table, USAGE on its schema, membersip of a role, and OWNERship+USAGE+CREATE of another schema:

```python
from pg_sync_roles import (
    RoleMembership,
    SchemaUsage,
    SchemaCreate,
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
            SchemaUsage('my_schema'),
            TableSelect('my_schema', 'my_table'),
            SchemaOwnership('my_other_schema'),
            SchemaUsage('my_other_schema'),
            SchemaCreate('my_other_schema'),
            RoleMembership('my_other_role'),
        ),
    )
```


## API

### Core function

#### `sync_roles(conn, role_name, grants=(), preserve_existing_grants_in_schemas=(), lock_key=1)`

- `conn`

   A SQLAlchemy connection with an engine of dialect `postgresql+psycopg` or `postgresql+psycopg2`. For SQLAlchemy < 2 `future=True` must be passed to its create_engine function.

- `role_name`

   The role name to grant and revoke permissions and role memberships from. If the role does not exist it will be automatically created.

- `grants=()`

   A tuple of grants of all permissions that the role specified by the `role_name` should have. Anything not in this list will be automatically revoked. See [Grant types](#grant-types) for the list of grant types.

- `preserve_existing_grants_in_schemas=()`

   A tuple of schema names. For each schema name `sync_roles` will leave any existing privileges granted on anything in the schema to `role_name` intact. This is useful in situations when the contents of the schemas are managed separately, outside of calls to `sync_roles`.

   A schema name being listed in `preserve_existing_grants_in_schemas` does not affect management of permissions on the the schema itself. In order for `role_name` to have privileges on these, they will have to be passed in via the `grants` parameter.

- `lock_key=1`

   The key for the advisory lock taken before changes are made. See [Locking](#locking) for more details.


### Grant types

#### `Login(password, valid_until)`

#### `DatabaseConnect(database_name)`

#### `SchemaUsage(schema_name)`

#### `SchemaCreate(schema_name)`

#### `TableSelect(schema_name, table_name)`

#### `RoleMembership(role_name)`

#### `SchemaOwnership(schema_name)`


## Locking

pg-sync-roles obtains an advisory exclusive lock before making any changes - this avoids "tuple concurrently updated" or "tuple concurrently deleted" errors that can be raised when multiple connections change or delete the same permissions-related rows. It does this by calling the `pg_advisory_xact_lock(key bigint)` function. By default a key of 1 is used, but this can be changed by passing a different integer key as the `lock_key` parameter to `sync_roles`.

If you have other processes changing permissions outide of the `sync_roles` function, they should first obtain the same lock by explicitly calling `pg_advisory_xact_lock(key bigint)` with the same key.

The advisory lock is only obtained if `sync_roles` detects there are changes to be made, and is released by the time it returns.


## Under the hood

pg-sync-roles maintains a role per database permission, a role per schema permission, and a role per table permission. Rather than roles being granted permissions directly on objects, membership is granted to these roles that indirectly grant permissions on objects. This means that from the object's point of view, only 1 role has any given permission. This works around the de-facto limit on the number of roles that can have permission to any object.

The names of the roles maintained by pg-sync-roles begin with the prefix `_pgsr_`. Each name ends with a randomly generated unique identifier.


## Compatibility

pg-sync-roles aims to be compatible with a wide range of Python and other dependencies:

- Python >= 3.7.1 (tested on 3.7.1, 3.8.0, 3.9.0, 3.10.0, and 3.11.0)
- psycopg2 >= 2.9.2 (tested on 3.9.2) and Psycopg 3 >= 3.1.4 (tested on 3.1.4)
- SQLAlchemy >= 1.4.24 (tested on 1.4.24 and 2.0.0)
- PostgreSQL >= 9.6 (tested on 9.6, 10.0, 11.0, 12.0, 13.0, 14.0, 15.0, and 16.0)

Note that SQLAlchemy < 2 does not support Psycopg 3, and for SQLAlchemy < 2 `future=True` must be passed to its create_engine function.

There are no plans to drop support for any of the above.


## Running tests locally

```bash
python -m pip install psycopg -e ".[dev]"  # Only needed once
./start-services.sh                        # Only needed once
pytest
```


## Design decisions

This information isn't needed to use pg-sync-roles, it's more for developers of pg-sync-roles itself.

### Existence of this project

It was factored out from https://github.com/uktrade/data-workspace-frontend, mostly from the "new_private_database_credentials" function, which was several hundred lines long and a bit "sprawling" - lots of duplication and it was hard to see what was going on.

Having it factored out makes it:

- Easier to test and develop for multiple versions of Python, PostgreSQL and other packages such as Psycopg and SQLAlchemy, and so give confidence to where it's used as packages are updated.
- Easier to reuse in other projects, and so better adhere to the "reuse" part of [Point 12 of the Service Standard](https://www.gov.uk/service-manual/service-standard). Interally in the DBT we now have 2 use cases for this - one on the data egress side as part of https://github.com/uktrade/data-workspace-frontend, and one on the ingest side.
- Easier to make/more strongly encourages a well defined and (eventually) well documented API that makes it clear exactly what permissions each user has, and makes it easier to change them.
- Easier to be maintained by a separate team to the one that maintains the user-facing components in https://github.com/uktrade/data-workspace-frontend.

None of this is impossible if the code stayed with https://github.com/uktrade/data-workspace-frontend, but it would make all the above more awkward. The confluence of all the above aspects made it seem worth the separation.


### Usage of roles

pg-sync-roles creates intermediate roles for ACL-type permissions like CONNECT, SELECT and USAGE. This is to support high numbers of users being granted these privileges.

There didn't really seem to be any viable alternative to maintain a way of granting per table+per user permissions in a system that had several thousand users such as Data Workspace. Without the roles when GRANTing there could be "row is too big" when the numbers of grantees on an object reaches around 2 thousand. This is because many of the catalog tables do not support the PostgreSQL TOAST system, and so a value in the row, such as the acl field that stores the grantees on the object, is limited to a single database page, which by default is 8kb https://stackoverflow.com/a/57089028/1319998.

Apparently we can compile our own PostgreSQL with a bigger table size, but we wouldn't be able to run on Amazon RDS, or probably any managed service.

Also having high numbers of grantees on each object makes full table scans on the catalog tables very slow: 10 to 30 seconds to search though pg_class in Data Workspace for example.


### Structure of the role names

The role names have a unique identifier in them, but this is _not_ tied to any property of the object they are related to - they are randomly generated. While it maybe makes it a touch harder to see what object each role is for, this makes it fine to move permissions from one object to another, and everything will continue to work as expected. This makes certain ingests easier because they can swap a table with new table, copy all grantees from the old to the new, and everything will continue to work. Also tables can be renamed without any effect on their permissions.

Note that database clusters can have multiple databases on them, and roles are shared between all databases in a cluster. Also, some objects are shared between all databases (strangely, those in pg_databases itself), and some are just visible to the currently connected database (for example pg_class). To support efficiently working just on a single database on a time in future versions, the role names on objects that are private to a single database also contain the oid of the corresponding row in pg_database. This is a slight "just in case" feature, but the overhead is minimial and it keeps options open for the future - for example to only revoke permissions on the currently connected database if there are multiple databases at play.


### A declarative API

The API is not one that offers, for example, a "give a role this permission in addition to what they already have", but instead requires a full list of permissions, and pg-sync-roles works out what changes needs to be made and makes them. While this means there is quite a lot of code in pg-sync-roles:

- pg-sync-roles is "self correcting" - if a change is lost, or manually undone in the database somehow, it will be fixed.
- pg-sync-roles supports cases where, for example, a full list of permissions is stored in a config file and there isn't really a "one at a time" process
