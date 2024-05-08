# pg-sync-roles

Python utility function to ensure that a PostgreSQL role has certain permissions or role memberships

> [!WARNING]  
> Work in progress. This README serves as a rough design spec.

## Features

- Transparently handles high numbers of permissions - avoiding "row is too big" errors.
- Locks where necessary - working around "tuple concurrently updated" or "tuple concurrently deleted" errors".
- Optionally removes permissions from roles
- Handles database connect, schema usage, table select permissions, and role memberships - typically useful when using PostgreSQL as a data warehouse with a high number of users that need granular permissions.


## Installation

pg-sync-rolescan be installed from PyPI using pip. psycopg2 or psycopg (Psycopg 3) must also be explicitly installed.

```bash
pip install pg-sync-roles psycopg
```
