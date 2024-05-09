import uuid

import pytest
import sqlalchemy as sa

try:
    # psycopg2
    import psycopg2
    engine_type = 'postgresql+psycopg2'
except ImportError:
    # psycopg3
    import psycopg
    engine_type = 'postgresql+psycopg'

engine_future = {'future': True} if tuple(int(v) for v in sa.__version__.split('.')) < (2, 0, 0) else {}

from pg_sync_roles import sync_roles, DatabaseConnect

# By 4000 roles having permission to something, we get "row is too big" errors, so it's a good
# number to test on to make sure we don't hit that issue
ROLES_PER_TEST = 4000


# We make and drop a database in each test to keep them isolated
TEST_DATABASE_NAME = 'pg_sync_roles_test'


@pytest.fixture()
def root_engine():
    return sa.create_engine(f'{engine_type}://postgres@127.0.0.1:5432/', **engine_future)


@pytest.fixture()
def test_engine(root_engine):
    def drop_database_if_exists(conn):
        # Recent versions of PostgreSQL have a `WITH (force)` option to DROP DATABASE which kills
        # conections, but we run tests on older versions that don't support this.
        conn.execute(sa.text(f'''
            SELECT pg_terminate_backend(pg_stat_activity.pid)
            FROM pg_stat_activity
            WHERE pg_stat_activity.datname = '{TEST_DATABASE_NAME}'
            AND pid != pg_backend_pid();
        '''));
        conn.execute(sa.text(f'DROP DATABASE IF EXISTS {TEST_DATABASE_NAME}'))

    with root_engine.connect() as conn:
        conn.execution_options(isolation_level='AUTOCOMMIT')
        drop_database_if_exists(conn)
        conn.execute(sa.text(f'CREATE DATABASE {TEST_DATABASE_NAME}'))

    yield sa.create_engine(f'{engine_type}://postgres@127.0.0.1:5432/{TEST_DATABASE_NAME}', **engine_future)

    with root_engine.connect() as conn:
        conn.execution_options(isolation_level='AUTOCOMMIT')
        drop_database_if_exists(conn)


@pytest.fixture()
def sync_engine(test_engine):
    return sa.create_engine(f'{engine_type}://postgres@127.0.0.1:5432/{TEST_DATABASE_NAME}', **engine_future)


def test_many_roles_with_database_connect_does_not_raise_exception(test_engine):
    with test_engine.connect() as conn:
        for role_name in (uuid.uuid4().hex for _ in range(0, ROLES_PER_TEST)):
            sync_roles(conn, role_name, grants=(
                DatabaseConnect('postgres'),
            ))


def test_database_connect_does_not_accumulate_roles(test_engine, sync_engine):
    role_name = uuid.uuid4().hex

    with \
            test_engine.connect() as conn_test, \
            sync_engine.connect() as conn_sync:

        conn_test.execute(sa.text('SELECT count(*) FROM pg_roles')).fetchall()[0][0]
        conn_test.execute(sa.text('SELECT count(*) FROM pg_roles')).fetchall()[0][0]

        count_roles_1 = conn_test.execute(sa.text('SELECT count(*) FROM pg_roles')).fetchall()[0][0]

        sync_roles(conn_sync, role_name)

        count_roles_2 = conn_test.execute(sa.text('SELECT count(*) FROM pg_roles')).fetchall()[0][0]

        sync_roles(conn_sync, role_name, grants=(
            DatabaseConnect(TEST_DATABASE_NAME),
        ))

        count_roles_3 = conn_test.execute(sa.text('SELECT count(*) FROM pg_roles')).fetchall()[0][0]

        sync_roles(conn_sync, role_name, grants=(
            DatabaseConnect(TEST_DATABASE_NAME),
        ))

        count_roles_4 = conn_test.execute(sa.text('SELECT count(*) FROM pg_roles')).fetchall()[0][0]

        assert count_roles_2 == count_roles_1 + 1
        assert count_roles_3 == count_roles_2 + 1
        assert count_roles_4 == count_roles_3


def test_sync_role_for_one_user(test_engine):
    role_name = uuid.uuid4().hex
    database_query = f'''
            SELECT has_database_privilege('{role_name}', '{TEST_DATABASE_NAME}', 'CONNECT') 
        '''
    with test_engine.connect() as conn:
        sync_roles(conn, role_name, grants=(
                DatabaseConnect(TEST_DATABASE_NAME),
            ))
        
        assert conn.execute(sa.text(database_query)).fetchall()[0][0]
