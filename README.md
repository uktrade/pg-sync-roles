# pg-sync-roles [![PyPI package](https://img.shields.io/pypi/v/pg-sync-roles?label=PyPI%20package)](https://pypi.org/project/pg-sync-roles/) [![Test suite](https://img.shields.io/github/actions/workflow/status/uktrade/pg-sync-roles/test.yaml?label=Test%20suite)](https://github.com/uktrade/pg-sync-roles/actions/workflows/test.yaml) [![Code coverage](https://img.shields.io/codecov/c/github/uktrade/pg-sync-roles?label=Code%20coverage)](https://app.codecov.io/gh/uktrade/pg-sync-roles)

Python utility functions to ensure that PostgreSQL roles have certain privileges on database objects or memberships of other roles - useful to periodically synchronise PostgreSQL's role and privilege system with an external store.

> [!IMPORTANT]
> While pg-sync-roles removes the need of a lot of the boilerplate in order to manage permissions, it is a light abstraction layer over the PostgreSQL permission system. Therefore to use pg-sync-roles effectively and securely, you should have knowledge of:
>
> - [PostgreSQL privileges](https://www.postgresql.org/docs/current/ddl-priv.html)
> - [PostgreSQL role attributes](https://www.postgresql.org/docs/current/role-attributes.html)
> - [PostgreSQL database roles](https://www.postgresql.org/docs/current/user-manag.html)

---

### Contents

Using pg-sync-roles

- [Features](#features)
- [Installation](#installation)
- [Usage examples](#usage-examples)
- [API](#api)
- [Locking](#locking)
- [Intermediate roles](#intermediate-roles)
- [Compatibility](#compatibility)

Developing pg-sync-roles

- [Running tests locally](#running-tests-locally)
- [Testing strategy](#testing-strategy)
- [Mitigating SQL injection risks](#mitigating-sql-injection-risks)
- [Internal flow](#internal-flow)
- [Design decisions](#design-decisions)

---

## Features

- Handles high numbers of permissions on database objects - avoiding "row is too big" errors by transparently creating and using intermediate roles
- Also can minimise role memberships by optionally avoiding the intermediate role for certain grant types
- Locks where necessary - working around "tuple concurrently updated" or "tuple concurrently deleted" errors that can happen when permission changes are performed concurrently.
- Does _not_ require the connecting user to be SUPERUSER
- Can grant (and so automatically revokes if not requested):
  -  Login (with password and expiry)
  -  Role memberships
  -  Database CONNECT
  -  Schema USAGE, CREATE, and ownership
  -  Table (and table-like) SELECT
- Automatically revokes all non-SELECT permissions on table-like objects, for example INSERT.
- Table-like objects for SELECT permissions can be chosen by a regular expression match on their name, for example to choose all tables in a schema or all tables that start with a prefix
- Allows for contents of specific schemas to be ignored for the purposes of management of permissions

 These features make pg-sync-roles useful when using PostgreSQL as a data warehouse with a high number of users that need granular permissions. The lack of SUPERUSER requirement means that pg-sync-roles is suitable for managed PostgreSQL clusters, for example in Amazon RDS.
 
 Other types of privileges and other object types may be added in future versions.

> [!WARNING]
> pg-sync-roles does not revoke any permissions granted to the PUBLIC pseudo-role


## Installation

pg-sync-roles can be installed from PyPI using pip. psycopg2 or psycopg (Psycopg 3) must also be explicitly installed.

```bash
pip install pg-sync-roles psycopg
```


## Usage examples

The core function of pg-sync-roles is the `sync_roles` function: it is used to manage what a single role is able to do and its memberships of other roles. To use this function, you must have a PostgreSQL database. To quickly set one up locally to test the following examples, you can run:

```bash
docker run --rm -it -e POSTGRES_HOST_AUTH_METHOD=trust -p 5432:5432 postgres
```

- [Login and CONNECT to a database](#login-and-connect-to-a-database)
- [SELECT on a single table and USAGE on its schema](#select-on-a-table-and-usage-on-its-schema)
- [SELECT on multiple tables matching a regular expression](#select-on-multiple-tables-matching-a-regular-expression)
- [OWNERship, USAGE, and CREATE on a schema](#select-on-a-table-and-usage-on-its-schema)
- [Membership of other roles](#membership-of-other-roles)
- [Hierarchy of roles](#hierarchy-of-roles)

### Login and CONNECT to a database

To give a role the ability to login (making the role more of a user) with a random password valid for 28 days and the ability to CONNECT to a database:

```python
import string
import secrets
from datetime import datetime, timedelta, timezone
from pg_sync_roles import *

password_alphabet = string.ascii_letters + string.digits
password = ''.join(secrets.choice(password_alphabet) for i in range(64))
valid_until = datetime.now(timezone.utc) + timedelta(days=28)

with sa.create_engine('postgresql+psycopg://postgres@127.0.0.1:5432/').connect() as conn:
    sync_roles(
        conn,
        'my_user',
        grants=(
            Login(password=password, valid_until=valid_until),
            DatabaseConnect('my_database'),
        ),
    )
```

> [!WARNING]
> pg-sync-roles should not be used on roles that should have permissions to multiple database in a cluster (although this limitation may be removed in future versions).

### SELECT on a single table and USAGE on its schema

To give a role SELECT on a table, USAGE on its schema using [intermediate roles](#intermediate-roles):

```python
import sqlalchemy as sa
from pg_sync_roles import *

with sa.create_engine('postgresql+psycopg://postgres@127.0.0.1:5432/').connect() as conn:
    sync_roles(
        conn,
        'my_role',
        grants=(
            SchemaUsage('my_schema'),
            TableSelect('my_schema', 'my_table'),
        ),
    )
```

Or to do the same thing but _without_ using [intermediate roles](#intermediate-roles):

```python
import sqlalchemy as sa
from pg_sync_roles import *

with sa.create_engine('postgresql+psycopg://postgres@127.0.0.1:5432/').connect() as conn:
    sync_roles(
        conn,
        'my_role',
        grants=(
            SchemaUsage('my_schema', direct=True),
            TableSelect('my_schema', 'my_table', direct=True),
        ),
    )
```

Avoiding intermediate roles can be useful to avoid performance problems on connection when the connecting user has a high number of role memberships when dealing with thousands of tables and thousands of users. Because `direct=True` adds the role to the ACL on the underlying database object, it is subject to the de-facto limit on how many roles can be granted access on an object, and so you should not do this with more than ~1000 roles granted permissions on a single object.

### SELECT on multiple tables matching a regular expression

To grant USAGE on a schema and SELECT on all tables in that schema that match a regular expression:

```python
import re
import sqlalchemy as sa
from pg_sync_roles import *

with sa.create_engine('postgresql+psycopg://postgres@127.0.0.1:5432/').connect() as conn:
    sync_roles(
        conn,
        'my_role',
        grants=(
            SchemaUsage('my_schema'),
            TableSelect('my_schema', re.compile('my_table_prefix_.+')),
        ),
    )
```

### OWNERship, USAGE, and CREATE on a schema

To give a role OWNERship, USAGE, and CREATE on a schema:

```python

import sqlalchemy as sa
from pg_sync_roles import *

with sa.create_engine('postgresql+psycopg://postgres@127.0.0.1:5432/').connect() as conn:
    sync_roles(
        conn,
        'my_role',
        grants=(
            SchemaOwnership('my_schema'),
            SchemaUsage('my_schema'),
            SchemaCreate('my_schema'),
        ),
    )
```

### Membership of other roles

To give a role membership of another role:

```python
import sqlalchemy as sa
from pg_sync_roles import *

with sa.create_engine('postgresql+psycopg://postgres@127.0.0.1:5432/').connect() as conn:
    sync_roles(
        conn,
        'my_role',
        grants=(
            RoleMembership('my_other_role'),
        ),
    )
```

### Hierarchy of roles

A hierarchy/tree of roles can be managed with multiple calls to sync_roles:

```python
import sqlalchemy as sa
from pg_sync_roles import *

with sa.create_engine('postgresql+psycopg://postgres@127.0.0.1:5432/').connect() as conn:
    sync_roles(
        conn,
        'my_user',
        grants=(
            Login(password=password, valid_until=valid_until),
            DatabaseConnect('my_database'),
            RoleMembership('my_role'),
        ),
    )
    sync_roles(
        conn,
        'my_role',
        grants=(
            SchemaOwnership('my_personal_schema'),
            SchemaUsage('my_personal_schema'),
            SchemaCreate('my_personal_schema'),
            SchemaUsage('a_schema'),
            TableSelect('a_schema', 'a_table'),
            RoleMembership('a_shared_role'),
        ),
    )
    sync_roles(
        conn,
        'a_shared_role',
        grants=(
            SchemaOwnership('a_shared_writable_schema'),
            SchemaUsage('a_shared_writable_schema'),
            SchemaCreate('a_shared_writable_schema'),
            SchemaUsage('a_shared_readable_schema', direct=True),
            TableSelect('a_shared_readable_schema', 'a_table', direct=True),
        ),
    )
```

A more [complex example of using multiple calls to `sync_roles` can be found in the data-workspace-frontend codebase](https://github.com/uktrade/data-workspace-frontend/blob/cf50cf0cecfa79cdf0fad356ed71cc293662b0c4/dataworkspace/dataworkspace/apps/core/utils.py#L153).


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

#### `Login(valid_until=Optional[datetime], password=Optional[str])`

Gives the ability to login with `password` until `valid_until`.

- If `valid_until` is `None`, then the role can login forever.
- If `password` is `None`, then any existing password is preserved.

#### `DatabaseConnect(database_name)`

#### `SchemaUsage(schema_name, direct=False)`

#### `SchemaCreate(schema_name, direct=False)`

#### `TableSelect(schema_name, table_name: str|re.Pattern, direct=False)`

#### `RoleMembership(role_name)`

#### `SchemaOwnership(schema_name)`


### Function to delete unused/orphan roles

The DatabaseConnect, SchemaUsage, SchemaCreate, and TableSelect grant types result can result in unused/orphan roles if the objects they relate to are deleted. To delete all of these unused roles, you can periodically call the function `delete_unused_roles`.

#### `delete_unused_roles(conn, lock_key=1)`

- `conn`

   A SQLAlchemy connection with an engine of dialect `postgresql+psycopg` or `postgresql+psycopg2`. For SQLAlchemy < 2 `future=True` must be passed to its create_engine function.

- `lock_key=1`

   The key for the advisory lock taken before changes are made. See [Locking](#locking) for more details.


## Locking

pg-sync-roles obtains an advisory exclusive lock before making any changes - this avoids "tuple concurrently updated" or "tuple concurrently deleted" errors that can be raised when multiple connections change or delete the same permissions-related rows. It does this by calling the `pg_advisory_xact_lock(key bigint)` function. By default a key of 1 is used, but this can be changed by passing a different integer key as the `lock_key` parameter to `sync_roles`.

If you have other processes changing permissions outide of the `sync_roles` function, they should first obtain the same lock by explicitly calling `pg_advisory_xact_lock(key bigint)` with the same key.

The advisory lock is only obtained if `sync_roles` detects there are changes to be made, and is released by the time it returns.


## Intermediate roles

The default behaviour for pg-sync-roles is to maintain a role per database permission, a role per schema permission, and a role per table permission. Rather than roles being granted permissions directly on objects, membership is granted to these roles that indirectly grant permissions on objects. This means that from the object's point of view, only 1 role has any given permission. This works around the de-facto limit on the number of roles that can have permission to any object.

If the `TableSelect`, `SchemaUsage` or `SchemaCreate` grant types are constructed with `direct=True`, then the role is granted permission directly on the object without use of an intermediate role. This can be useful to minimise the number of role memberships; in some cases [a high number of role memberships can result in the connecting user taking an extremely long time to connect to the database](https://www.postgresql.org/message-id/CAJe2WWhxzbt_uszVYnyfw4Y%2BOdeHXdue0GD%2BOd5uk15XD_FL5w%40mail.gmail.com).

The names of the roles maintained by pg-sync-roles begin with the prefix `_pgsr_`. Each name ends with a randomly generated unique identifier.


## Compatibility

pg-sync-roles aims to be compatible with a wide range of Python and other dependencies:

- Python >= 3.7.1 (tested on 3.7.1, 3.8.0, 3.9.0, 3.10.0, 3.11.0, 3.12.0 and 3.13.0)
- psycopg2 >= 2.9.2 for Python < 3.13.0 (tested on 3.9.2), or psycopg2 >= 2.9.10 for Python 3.13 (tested on 2.9.10) and Psycopg 3 >= 3.1.4 for all supported versions of Python (tested on 3.1.4)
- SQLAlchemy >= 1.4.24, other than between 2.0.0 and 2.0.30 on Python 3.13 (tested on 1.4.24 and 2.0.0 for Python < 3.13.0, and 2.0.31 for Python 3.13.0)
- PostgreSQL >= 9.6 (tested on 9.6, 10.0, 11.0, 12.0, 13.0, 14.0, 15.0, 16.0 and 17.0)

Note that SQLAlchemy < 2 does not support Psycopg 3, and for SQLAlchemy < 2 `future=True` must be passed to its create_engine function.

There are no plans to drop support for any of the above.


---

The following sections aren't needed to use pg-sync-roles; they are more for developers of pg-sync-roles itself.


## Running tests locally

```bash
python -m pip install psycopg -e ".[dev]"  # Only needed once
./start-services.sh                        # Only needed once
pytest
```


## Testing strategy

Wherever possible tests are high-level integration tests, connecting to a real database and asserting on whether or not a role has permissions to take actions in the database, and running tests on multiple versions of PostgreSQL. Assertions on lower level behaviours, such as what queries are issues to the database during execution, are avoided because the they won't give the same guarentees on what users/roles have permissions to do. Mocking is avoided for similar reasons: it introduces assumptions.

A high level of code coverage (100% or close to 100%) is desired, but it is not sufficient. "Test around" any feature, adding a variety of cases, and especially making sure that access can be _removed_, not just granted.


## Mitigating SQL injection risks

> [!CAUTION]
> If you don't follow the instructions in this section you risk introducing vulnerabilities

ORM-like features are not used in pg-sync-roles, but instead queries are constructed directly. This gives flexibility, especially around optimisation, but introduces risks of SQL injection. This is even higher than in typical web applications because dynamic SQL is used heavily: dynamic in the sense that not only literals come from input, but identifiers and keywords as well.

To migitate this risk:

1. Queries must be constructed using psycopg's [sql.SQL](https://www.psycopg.org/psycopg3/docs/api/sql.html)
2. Literals from input must be escaped with [sql.Literal](https://www.psycopg.org/psycopg3/docs/api/sql.html#psycopg.sql.SQL)
3. Identifiers from input must be escaped with [sql.Identifier](https://www.psycopg.org/psycopg3/docs/api/sql.html#psycopg.sql.Identifier)
4. Keywords from input must be chosen from a safe-list of hard-coded [sql.SQL](https://www.psycopg.org/psycopg3/docs/api/sql.html) instances

For the avoidance of doubt, "input" covers anything that isn't hard-coded, and specifically covers both values passed into functions and values retrieved from the database.


## Internal flow

Following details the main internal behaviour of `sync_roles`. It's not exhaustive, but should be fairly representative and a conceptual "way in" to understand what's going on.

1. Perform basic validation
2. Start transaction
3. Work out changes to be made to existing permissions
4. Exit early if there are no changes to be made
5. Obtain advisory lock
6. Again work out changes to be made to existing permissions (with lock so avoiding making the same changes multiple times)
7. Temporarily grant the connecting user roles necessary to make changes
8. Make all required indirect permission changes to database objects
9. Apply changes of ownerships of objects
10. Find existing direct permissions on objects (required since changing ownerships can change direct permissions)
11. Change required direct permissions on objects
12. Revoke the temporary roles from the connecting user
13. Grant and revoke membership of roles
14. Commit transaction


## Design decisions

- [Existence of this project](#existence-of-this-project)
- [Usage of intermediate roles](#usage-of-intermediate-roles)
- [Avoiding usage of intermediate roles for some cases](#avoiding-usageo-of-intermediate-roles-for-some-cases)
- [Structure of the intermediate role names](#structure-of-the-intermediate-role-names)
- [A declarative API](#a-declarative-api)

### Existence of this project

It was factored out from https://github.com/uktrade/data-workspace-frontend, mostly from the "new_private_database_credentials" function, which was several hundred lines long and a bit "sprawling" - lots of duplication and it was hard to see what was going on.

Having it factored out makes it:

- Easier to test and develop for multiple versions of Python, PostgreSQL and other packages such as Psycopg and SQLAlchemy, and so give confidence to where it's used as packages are updated.
- Easier to reuse in other projects, and so better adhere to the "reuse" part of [Point 12 of the Service Standard](https://www.gov.uk/service-manual/service-standard). Interally in the DBT we now have 2 use cases for this - one on the data egress side as part of https://github.com/uktrade/data-workspace-frontend, and one on the ingest side.
- Easier to make/more strongly encourages a well defined and (eventually) well documented API that makes it clear exactly what permissions each user has, and makes it easier to change them.
- Easier to be maintained by a separate team to the one that maintains the user-facing components in https://github.com/uktrade/data-workspace-frontend.

None of this is impossible if the code stayed with https://github.com/uktrade/data-workspace-frontend, but it would make all the above more awkward. The confluence of all the above aspects made it seem worth the separation.


### Usage of intermediate roles

pg-sync-roles creates intermediate roles for ACL-type permissions like CONNECT, SELECT and USAGE. This is to support high numbers of users being granted these privileges.

There didn't really seem to be any viable alternative to maintain a way of granting per table+per user permissions in a system that had several thousand users such as Data Workspace. Without the roles when GRANTing there could be "row is too big" when the numbers of grantees on an object reaches around 2 thousand. This is because many of the catalog tables do not support the PostgreSQL TOAST system, and so a value in the row, such as the acl field that stores the grantees on the object, is limited to a single database page, which by default is 8kb https://stackoverflow.com/a/57089028/1319998.

Apparently we can compile our own PostgreSQL with a bigger table size, but we wouldn't be able to run on Amazon RDS, or probably any managed service.

Also having high numbers of grantees on each object makes full table scans on the catalog tables very slow: 10 to 30 seconds to search though pg_class in Data Workspace for example.


### Avoiding usage of intermediate roles for some cases

For table SELECT, schema USAGE, and schema CREATE, the grant types support a `direct=True` mode that avoids the intermediate roles. This is because we had a system where for users with high numbers of intermediate roles, two to three thousand, "sometimes" it would take > 90 seconds to initiate a connection to the database, while users with low numbers of roles would consistently connect almost instantly.

The reasons for this was never discovered, and exactly what "sometimes" was never pinned down — although calling CREATE ROLE seemed to be highly corrolated with subsequent slow connection times. However, since this setup had thousands of roles and _millions_ of rows in `pg_auth_members`, it felt like a situation that PostgreSQL was not designed for. By judicious use of `direct=True`, we could reduce the amount of role memberships for users by 1-2 orders of magnitude.


### Structure of the intermediate role names

The role names have a unique identifier in them, but this is _not_ tied to any property of the object they are related to - they are randomly generated. While it maybe makes it a touch harder to see what object each role is for, this makes it fine to move permissions from one object to another, and everything will continue to work as expected. This makes certain ingests easier because they can swap a table with new table, copy all grantees from the old to the new, and everything will continue to work. Also tables can be renamed without any effect on their permissions.

Note that database clusters can have multiple databases on them, and roles are shared between all databases in a cluster. Also, some objects are shared between all databases (strangely, those in pg_databases itself), and some are just visible to the currently connected database (for example pg_class). To support efficiently working just on a single database on a time in future versions, the role names on objects that are private to a single database also contain the oid of the corresponding row in pg_database. This is a slight "just in case" feature, but the overhead is minimial and it keeps options open for the future - for example to only revoke permissions on the currently connected database if there are multiple databases at play.


### A declarative API

The API is not one that offers, for example, a "give a role this permission in addition to what they already have", but instead requires a full list of permissions, and pg-sync-roles works out what changes needs to be made and makes them. While this means there is quite a lot of code in pg-sync-roles:

- pg-sync-roles is "self correcting" - if a change is lost, or manually undone in the database somehow, it will be fixed.
- pg-sync-roles supports cases where, for example, a full list of permissions is stored in a config file and there isn't really a "one at a time" process
