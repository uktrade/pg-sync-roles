import functools
import threading
import time
import uuid
from datetime import datetime, timezone, timedelta

import pytest
import sqlalchemy as sa
import wrapt

try:
    # psycopg2
    import psycopg2
    engine_type = 'postgresql+psycopg2'
except ImportError:
    # psycopg3
    import psycopg
    engine_type = 'postgresql+psycopg'

engine_future = {'future': True} if tuple(int(v) for v in sa.__version__.split('.')) < (2, 0, 0) else {}

from pg_sync_roles import sync_roles, DatabaseConnect, SchemaUsage, TableSelect, Login, RoleMembership


# By 4000 roles having permission to something, we get "row is too big" errors, so it's a good
# number to test on to make sure we don't hit that issue
ROLES_PER_TEST = 4000

# The default/root database that comes with the PostgreSQL Docker image
ROOT_DATABASE_NAME = 'postgres'

# We make and drop a database in each test to keep them isolated
TEST_DATABASE_NAME = 'pg_sync_roles_test'
TEST_BASE_ROLE = 'test_pgsr_base_role'


def get_test_role():
    return 'test_' + uuid.uuid4().hex


def is_member(conn, child_role_name, parent_role_name):
    query = f'''
        SELECT EXISTS (
            SELECT 1 FROM pg_auth_members
            WHERE member = :child_role_name ::regrole
            AND roleid = :parent_role_name ::regrole
        )
    '''
    return conn.execute(sa.text(query), {
        'child_role_name': child_role_name,
        'parent_role_name': parent_role_name,
    }).fetchall()[0][0]


@pytest.fixture()
def root_engine():
    return sa.create_engine(f'{engine_type}://postgres:postgres@127.0.0.1:5432/{ROOT_DATABASE_NAME}', **engine_future)


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
        '''))
        conn.execute(sa.text(f'DROP DATABASE IF EXISTS {TEST_DATABASE_NAME}'))
        roles = conn.execute(sa.text('''
            SELECT rolname FROM pg_roles WHERE rolname LIKE 'test\\_%' OR rolname LIKE '\\_pgsr\\_%'
        ''')).fetchall()
        for role, in roles:
            conn.execute(sa.text(f"REVOKE ALL PRIVILEGES ON DATABASE {ROOT_DATABASE_NAME} FROM {role}"))
            conn.execute(sa.text(f"DROP ROLE {role}"))

    with root_engine.connect() as conn:
        conn.execution_options(isolation_level='AUTOCOMMIT')
        drop_database_if_exists(conn)
        conn.execute(sa.text(f'CREATE DATABASE {TEST_DATABASE_NAME}'))
        conn.execute(sa.text(f'REVOKE CONNECT ON DATABASE {TEST_DATABASE_NAME} FROM PUBLIC'))

    yield sa.create_engine(f'{engine_type}://postgres:postgres@127.0.0.1:5432/{TEST_DATABASE_NAME}', **engine_future)

    with root_engine.connect() as conn:
        conn.execution_options(isolation_level='AUTOCOMMIT')
        drop_database_if_exists(conn)


@pytest.fixture()
def test_table(test_engine):
    schema_name = 'test_schema_' + uuid.uuid4().hex
    table_name = 'test_table_' + uuid.uuid4().hex

    with test_engine.begin() as conn:
        conn.execute(sa.text(f'CREATE SCHEMA {schema_name}'))
        conn.execute(sa.text(f'CREATE TABLE {schema_name}.{table_name} (id int)'))
    
    yield schema_name, table_name

    with test_engine.begin() as conn:
        conn.execute(sa.text(f'DROP TABLE IF EXISTS {schema_name}.{table_name}'))
        conn.execute(sa.text(f'DROP SCHEMA IF EXISTS {schema_name}'))


def test_many_roles_with_database_connect_does_not_raise_exception(test_engine):
    with test_engine.connect() as conn:
        for role_name in (uuid.uuid4().hex for _ in range(0, ROLES_PER_TEST)):
            sync_roles(conn, role_name, grants=(
                DatabaseConnect(TEST_DATABASE_NAME),
            ))


def test_if_cannot_choose_database_role_name_runtime_exception_raised(test_engine, monkeypatch):
    role_name = get_test_role()
    mock_hex = 'abcdefgh'
    monkeypatch.setattr(uuid.UUID, 'hex', mock_hex)

    with test_engine.begin() as conn:
        conn.execute(sa.text('CREATE ROLE _pgsr_global_database_connect_abcdefgh'))

    with test_engine.connect() as conn:
        with pytest.raises(RuntimeError, match='Unable to find available role name'):
            sync_roles(conn, role_name, grants=(
                DatabaseConnect(TEST_DATABASE_NAME),
            ))


def test_database_connect_does_not_accumulate_roles(test_engine):
    role_name = get_test_role()

    with \
            test_engine.connect() as conn_test, \
            test_engine.connect() as conn_sync:

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


@pytest.mark.parametrize('grants', [
    (),
    (Login(valid_until=datetime(2000,1,1, tzinfo=timezone.utc)),),
    (DatabaseConnect(TEST_DATABASE_NAME),),
    (RoleMembership(TEST_BASE_ROLE),),
])
def test_initial_grant_takes_lock(test_engine, grants):
    role_name = get_test_role()
    got_lock = threading.Event()
    num_blocked = 0

    def take_lock():
        nonlocal num_blocked

        with test_engine.connect() as conn:
            conn.execute(sa.text('SELECT pg_advisory_xact_lock(1)'))
            got_lock.set()
            for _ in range(0, 50):
                # We don't use pg_blocking_pids because sometimes, especially in CI, it seems
                # to repeatedly return nothing, even if we're pretty sure something is blocked
                num_blocked = conn.execute(sa.text('''
                    SELECT count(*)
                    FROM pg_locks
                    WHERE locktype = 'advisory' AND granted = FALSE
                ''')).fetchall()[0][0]
                if num_blocked:
                    break
                time.sleep(0.2)

    t = threading.Thread(target=take_lock)
    t.start()

    with test_engine.connect() as conn:
        got_lock.wait(timeout=5)
        sync_roles(conn, role_name, grants=grants, lock_key=1)

    t.join(timeout=15)
    assert num_blocked


@pytest.mark.parametrize('grants', [
    (),
    (Login(valid_until=datetime(2000,1,1, tzinfo=timezone.utc)),),
    (DatabaseConnect(TEST_DATABASE_NAME),),
    (RoleMembership(TEST_BASE_ROLE),),
])
def test_identical_grant_does_not_take_lock(test_engine, grants):
    role_name = get_test_role()

    done = threading.Event()

    def terminate_all_backends_after_five_seconds():
        done.wait(timeout=2)
        with test_engine.connect() as conn:
            conn.execute(sa.text(f'''
                SELECT pg_terminate_backend(pg_stat_activity.pid)
                FROM pg_stat_activity
                WHERE pg_stat_activity.datname = '{TEST_DATABASE_NAME}'
                AND pid != pg_backend_pid();
            '''))

    t = threading.Thread(target=terminate_all_backends_after_five_seconds)
    t.start()

    with \
            test_engine.connect() as conn_test, \
            test_engine.connect() as conn_sync:

        sync_roles(conn_sync, role_name, grants=grants, lock_key=1)
        conn_test.execute(sa.text('SELECT pg_advisory_xact_lock(1)'))
        sync_roles(conn_sync, role_name, grants=grants, lock_key=1)

    done.set()
    t.join(timeout=4)


@pytest.mark.parametrize('grants', [
    (),
    (Login(valid_until=datetime(2000,1,1, tzinfo=timezone.utc)),),
    (DatabaseConnect(TEST_DATABASE_NAME),),
    (RoleMembership(TEST_BASE_ROLE),),
])
def test_lock_can_timeout_and_connection_is_usable(test_engine, grants):
    role_name = get_test_role()

    with \
            test_engine.connect() as conn_test, \
            test_engine.connect() as conn_sync:

        conn_test.execute(sa.text('SELECT pg_advisory_xact_lock(1)'))
        conn_sync.execute(sa.text("SET statement_timeout = '500ms'"))
        conn_sync.commit()

        with pytest.raises(sa.exc.OperationalError, match='canceling statement due to statement timeout'):
            sync_roles(conn_sync, role_name, grants=grants, lock_key=1)

        # Asserts that we've rolled back
        assert conn_sync.execute(sa.text('SELECT 1')).fetchall()[0][0] == 1


def test_sync_role_for_one_user(test_engine):
    role_name = get_test_role()
    database_query = f'''
            SELECT has_database_privilege('{role_name}', '{TEST_DATABASE_NAME}', 'CONNECT')
        '''
    with test_engine.connect() as conn:
        sync_roles(conn, role_name, grants=(
                DatabaseConnect(TEST_DATABASE_NAME),
            ))

        assert conn.execute(sa.text(database_query)).fetchall()[0][0]


def test_login_expired_valid_until_cannot_connect(test_engine):
    role_name = get_test_role()
    valid_until = datetime.now(timezone.utc) - timedelta(minutes=10)
    with test_engine.connect() as conn:
        sync_roles(conn, role_name, grants=(
            Login(valid_until=valid_until, password='password'),
            DatabaseConnect(TEST_DATABASE_NAME),
        ))

    engine = sa.create_engine(f'{engine_type}://{role_name}:password@127.0.0.1:5432/{TEST_DATABASE_NAME}', **engine_future)
    with pytest.raises(sa.exc.OperationalError, match='password authentication failed'):
        engine.connect()


def test_login_incorrect_password_cannot_connect(test_engine):
    role_name = get_test_role()
    valid_until = datetime.now(timezone.utc) + timedelta(minutes=10)
    with test_engine.connect() as conn:
        sync_roles(conn, role_name, grants=(
            Login(valid_until=valid_until, password='password'),
            DatabaseConnect(TEST_DATABASE_NAME),
        ))

    engine = sa.create_engine(f'{engine_type}://{role_name}:not-the-password@127.0.0.1:5432/{TEST_DATABASE_NAME}', **engine_future)
    with pytest.raises(sa.exc.OperationalError, match='password authentication failed'):
        engine.connect()


def test_login_is_only_applied_to_passed_role(test_engine):
    role_name_with_login = get_test_role()
    role_name_without_login = get_test_role()
    valid_until = datetime.now(timezone.utc) + timedelta(minutes=10)
    with test_engine.connect() as conn:
        sync_roles(conn, role_name_with_login, grants=(
            Login(valid_until=valid_until, password='password'),
            DatabaseConnect(TEST_DATABASE_NAME),
        ))
        sync_roles(conn, role_name_without_login, grants=(
            DatabaseConnect(TEST_DATABASE_NAME),
        ))

    engine = sa.create_engine(f'{engine_type}://{role_name_without_login}:password@127.0.0.1:5432/{TEST_DATABASE_NAME}', **engine_future)
    with pytest.raises(sa.exc.OperationalError, match='password authentication failed'):
        engine.connect()


def test_login_without_database_connect_cannot_connect(test_engine):
    role_name = get_test_role()
    valid_until = datetime.now(timezone.utc) + timedelta(minutes=10)
    with test_engine.connect() as conn:
        sync_roles(conn, role_name, grants=(
            Login(valid_until=valid_until, password='password'),
        ))

    engine = sa.create_engine(f'{engine_type}://{role_name}:password@127.0.0.1:5432/{TEST_DATABASE_NAME}', **engine_future)
    with pytest.raises(sa.exc.OperationalError, match='User does not have CONNECT privilege'):
        engine.connect()


def test_login_with_different_database_connect_cannot_connect(test_engine):
    role_name = get_test_role()
    valid_until = datetime.now(timezone.utc) + timedelta(minutes=10)
    with test_engine.connect() as conn:
        sync_roles(conn, role_name, grants=(
            Login(valid_until=valid_until, password='password'),
            DatabaseConnect(ROOT_DATABASE_NAME),
        ))

    engine = sa.create_engine(f'{engine_type}://{role_name}:password@127.0.0.1:5432/{TEST_DATABASE_NAME}', **engine_future)
    with pytest.raises(sa.exc.OperationalError, match='User does not have CONNECT privilege'):
        engine.connect()


def test_login_with_valid_until_initialy_future_but_changed_to_be_in_the_past_cannot_connect(test_engine):
    role_name = get_test_role()
    valid_until = datetime.now(timezone.utc) + timedelta(minutes=10)
    with test_engine.connect() as conn:
        sync_roles(conn, role_name, grants=(
            Login(valid_until=valid_until, password='password'),
            DatabaseConnect(TEST_DATABASE_NAME),
        ))
        sync_roles(conn, role_name, grants=(
            Login(valid_until=valid_until - timedelta(minutes=20), password='password'),
            DatabaseConnect(TEST_DATABASE_NAME),
        ))

    engine = sa.create_engine(f'{engine_type}://{role_name}:password@127.0.0.1:5432/{TEST_DATABASE_NAME}', **engine_future)
    with pytest.raises(sa.exc.OperationalError, match='password authentication failed'):
        engine.connect()


def test_login_with_with_connect_then_revoked_cannot_connect(test_engine):
    role_name = get_test_role()
    valid_until = datetime.now(timezone.utc) + timedelta(minutes=10)
    with test_engine.connect() as conn:
        sync_roles(conn, role_name, grants=(
            Login(valid_until=valid_until, password='password'),
            DatabaseConnect(TEST_DATABASE_NAME),
        ))
        sync_roles(conn, role_name, grants=(
            Login(valid_until=valid_until, password='password'),
        ))

    engine = sa.create_engine(f'{engine_type}://{role_name}:password@127.0.0.1:5432/{TEST_DATABASE_NAME}', **engine_future)
    with pytest.raises(sa.exc.OperationalError, match='User does not have CONNECT privilege'):
        engine.connect()


def test_login_with_with_connect_then_login_revoked_cannot_connect(test_engine):
    role_name = get_test_role()
    valid_until = datetime.now(timezone.utc) + timedelta(minutes=10)
    with test_engine.connect() as conn:
        sync_roles(conn, role_name, grants=(
            Login(valid_until=valid_until, password='password'),
            DatabaseConnect(TEST_DATABASE_NAME),
        ))
        sync_roles(conn, role_name, grants=(
            DatabaseConnect(TEST_DATABASE_NAME),
        ))

    engine = sa.create_engine(f'{engine_type}://{role_name}:password@127.0.0.1:5432/{TEST_DATABASE_NAME}', **engine_future)
    with pytest.raises(sa.exc.OperationalError, match='password authentication failed'):
        engine.connect()


def test_login_cannot_connect_with_old_password(test_engine):
    role_name = get_test_role()
    valid_until = datetime.now(timezone.utc) + timedelta(minutes=10)
    with test_engine.connect() as conn:
        sync_roles(conn, role_name, grants=(
            Login(valid_until=valid_until, password='password'),
            DatabaseConnect(TEST_DATABASE_NAME),
        ))
        sync_roles(conn, role_name, grants=(
            Login(valid_until=valid_until, password='newpasswrd'),
            DatabaseConnect(TEST_DATABASE_NAME),
        ))

    engine = sa.create_engine(f'{engine_type}://{role_name}:password@127.0.0.1:5432/{TEST_DATABASE_NAME}', **engine_future)
    with pytest.raises(sa.exc.OperationalError, match='password authentication failed'):
        engine.connect()


def test_login_can_connect(test_engine):
    role_name = get_test_role()
    valid_until = datetime.now(timezone.utc) + timedelta(minutes=10)
    with test_engine.connect() as conn:
        sync_roles(conn, role_name, grants=(
            Login(valid_until=valid_until, password='password'),
            DatabaseConnect(TEST_DATABASE_NAME),
        ))

    engine = sa.create_engine(f'{engine_type}://{role_name}:password@127.0.0.1:5432/{TEST_DATABASE_NAME}', **engine_future)
    with engine.connect() as conn:
        assert conn.execute(sa.text("SELECT 1")).fetchall()[0][0] == 1


def test_login_wrapt_can_connect(test_engine, monkeypatch):
    # Certain instrumentation (elastic-apm specifically) does not play well with psycopg2 because
    # it wraps the connection objects, which then do not pass its runtime type checking and raise
    # an exception when sql.SQL(...).as_string is called which sync_roles does under the hood
    #
    # This test simulates that case by wrapping the connection object.

    def wrapped_connect(original_connect, *args, **kwargs):
        return wrapt.ObjectProxy(original_connect(*args, **kwargs))

    def dummy_register_type(*args, **kwargs):
        pass

    try:
        import psycopg2
    except ImportError:
        pass
    else:
        monkeypatch.setattr(psycopg2, 'connect', functools.partial(wrapped_connect, psycopg2.connect))
        # This is to get the test to run - register_type fails with the wrapped connection for some
        # reason. This only seems to happen in this test environment for some reason, so we just
        # replace it with a dummy object to get the test to continue to the case we are testing
        monkeypatch.setattr(psycopg2.extensions, 'register_type', dummy_register_type)

    try:
        import psycopg
    except ImportError:
        pass
    else:
        monkeypatch.setattr(psycopg, 'connect', functools.partial(wrapped_connect, psycopg.connect))

    # We arbitrarily check any usage of sync_roles
    role_name = get_test_role()
    valid_until = datetime.now(timezone.utc) + timedelta(minutes=10)

    with test_engine.connect() as conn:
        sync_roles(conn, role_name, grants=(
            Login(valid_until=valid_until, password='password'),
            DatabaseConnect(TEST_DATABASE_NAME),
        ))

    engine = sa.create_engine(f'{engine_type}://{role_name}:password@127.0.0.1:5432/{TEST_DATABASE_NAME}', **engine_future)
    with engine.connect() as conn:
        assert conn.execute(sa.text("SELECT 1")).fetchall()[0][0] == 1


def test_login_can_connect_after_second_sync_by_no_password(test_engine):
    role_name = get_test_role()
    valid_until = datetime.now(timezone.utc) + timedelta(minutes=10)
    with test_engine.connect() as conn:
        sync_roles(conn, role_name, grants=(
            Login(valid_until=valid_until, password='password'),
            DatabaseConnect(TEST_DATABASE_NAME),
        ))
        sync_roles(conn, role_name, grants=(
            Login(valid_until=valid_until),
            DatabaseConnect(TEST_DATABASE_NAME),
        ))

    engine = sa.create_engine(f'{engine_type}://{role_name}:password@127.0.0.1:5432/{TEST_DATABASE_NAME}', **engine_future)
    with engine.connect() as conn:
        assert conn.execute(sa.text("SELECT 1")).fetchall()[0][0] == 1


def test_multiple_login_raises_value_error(test_engine):
    role_name = get_test_role()
    valid_until = datetime.now(timezone.utc) + timedelta(minutes=10)
    with test_engine.connect() as conn:
        with pytest.raises(ValueError):
            sync_roles(conn, role_name, grants=(
                Login(valid_until=valid_until, password='password'),
                Login(valid_until=valid_until, password='password'),
            ))


def test_role_membership_in_one_step(test_engine):
    role_name = get_test_role()
    with test_engine.connect() as conn:
        sync_roles(conn, role_name, grants=(
            RoleMembership(TEST_BASE_ROLE),
        ))
        assert is_member(conn, role_name, TEST_BASE_ROLE)


def test_role_membership_in_multiple_steps(test_engine):
    role_name = get_test_role()
    with test_engine.connect() as conn:
        sync_roles(conn, role_name)
        sync_roles(conn, role_name, grants=(
            RoleMembership(TEST_BASE_ROLE),
        ))
        assert is_member(conn, role_name, TEST_BASE_ROLE)


def test_role_membership_only_granted_to_passed_role(test_engine):
    role_name_1 = get_test_role()
    role_name_2 = get_test_role()
    with test_engine.connect() as conn:
        sync_roles(conn, role_name_1)
        sync_roles(conn, role_name_2, grants=(
            RoleMembership(TEST_BASE_ROLE),
        ))

        assert not is_member(conn, role_name_1, TEST_BASE_ROLE)
        assert is_member(conn, role_name_2, TEST_BASE_ROLE)


def test_role_membership_only_granted_to_multiple_roles(test_engine):
    role_name_1 = get_test_role()
    role_name_2 = get_test_role()
    with test_engine.connect() as conn:
        sync_roles(conn, role_name_1, grants=(
            RoleMembership(TEST_BASE_ROLE),
        ))
        sync_roles(conn, role_name_2, grants=(
            RoleMembership(TEST_BASE_ROLE),
        ))

        assert is_member(conn, role_name_1, TEST_BASE_ROLE)
        assert is_member(conn, role_name_2, TEST_BASE_ROLE)


def test_role_membership_revoked(test_engine):
    role_name = get_test_role()
    with test_engine.connect() as conn:
        sync_roles(conn, role_name, grants=(
            RoleMembership(TEST_BASE_ROLE),
        ))
        sync_roles(conn, role_name)

        assert not is_member(conn, role_name, TEST_BASE_ROLE)


def test_table_select_never_granted_cannot_query(test_engine, test_table):
    schema_name, table_name = test_table
    role_name = get_test_role()
    valid_until = datetime.now(timezone.utc) + timedelta(minutes=10)
    with test_engine.connect() as conn:
        sync_roles(conn, role_name, grants=(
            Login(valid_until=valid_until, password='password'),
            DatabaseConnect(TEST_DATABASE_NAME),
            SchemaUsage(schema_name),
            TableSelect(schema_name, table_name),
        ))
        sync_roles(conn, role_name, grants=(
            Login(valid_until=valid_until, password='password'),
            DatabaseConnect(TEST_DATABASE_NAME),
            SchemaUsage(schema_name),
        ))

    engine = sa.create_engine(f'{engine_type}://{role_name}:password@127.0.0.1:5432/{TEST_DATABASE_NAME}', **engine_future)
    with engine.connect() as conn:
        with pytest.raises(sa.exc.ProgrammingError, match='permission denied for (table|relation)'):
            assert conn.execute(sa.text(f"SELECT count(*) FROM {schema_name}.{table_name}")).fetchall()[0][0] == 0


def test_table_select_granted_then_revoked_cannot_query(test_engine, test_table):
    schema_name, table_name = test_table
    role_name = get_test_role()
    valid_until = datetime.now(timezone.utc) + timedelta(minutes=10)
    with test_engine.connect() as conn:
        sync_roles(conn, role_name, grants=(
            Login(valid_until=valid_until, password='password'),
            DatabaseConnect(TEST_DATABASE_NAME),
            SchemaUsage(schema_name),
            TableSelect(schema_name, table_name),
        ))
        sync_roles(conn, role_name, grants=(
            Login(valid_until=valid_until, password='password'),
            DatabaseConnect(TEST_DATABASE_NAME),
            SchemaUsage(schema_name),
        ))

    engine = sa.create_engine(f'{engine_type}://{role_name}:password@127.0.0.1:5432/{TEST_DATABASE_NAME}', **engine_future)
    with engine.connect() as conn:
        with pytest.raises(sa.exc.ProgrammingError, match='permission denied for (table|relation)'):
            assert conn.execute(sa.text(f"SELECT count(*) FROM {schema_name}.{table_name}")).fetchall()[0][0] == 0


def test_table_select_usage_never_granted_cannot_query(test_engine, test_table):
    schema_name, table_name = test_table
    role_name = get_test_role()
    valid_until = datetime.now(timezone.utc) + timedelta(minutes=10)
    with test_engine.connect() as conn:
        sync_roles(conn, role_name, grants=(
            Login(valid_until=valid_until, password='password'),
            DatabaseConnect(TEST_DATABASE_NAME),
            TableSelect(schema_name, table_name),
        ))

    engine = sa.create_engine(f'{engine_type}://{role_name}:password@127.0.0.1:5432/{TEST_DATABASE_NAME}', **engine_future)
    with engine.connect() as conn:
        with pytest.raises(sa.exc.ProgrammingError, match='permission denied for schema'):
            assert conn.execute(sa.text(f"SELECT count(*) FROM {schema_name}.{table_name}")).fetchall()[0][0] == 0


def test_table_select_granted_then_usage_revoked_cannot_query(test_engine, test_table):
    schema_name, table_name = test_table
    role_name = get_test_role()
    valid_until = datetime.now(timezone.utc) + timedelta(minutes=10)
    with test_engine.connect() as conn:
        sync_roles(conn, role_name, grants=(
            Login(valid_until=valid_until, password='password'),
            DatabaseConnect(TEST_DATABASE_NAME),
            SchemaUsage(schema_name),
            TableSelect(schema_name, table_name),
        ))
        sync_roles(conn, role_name, grants=(
            Login(valid_until=valid_until, password='password'),
            DatabaseConnect(TEST_DATABASE_NAME),
            TableSelect(schema_name, table_name),
        ))

    engine = sa.create_engine(f'{engine_type}://{role_name}:password@127.0.0.1:5432/{TEST_DATABASE_NAME}', **engine_future)
    with engine.connect() as conn:
        with pytest.raises(sa.exc.ProgrammingError, match='permission denied for schema'):
            assert conn.execute(sa.text(f"SELECT count(*) FROM {schema_name}.{table_name}")).fetchall()[0][0] == 0


def test_table_select_granted_can_query(test_engine, test_table):
    schema_name, table_name = test_table
    role_name = get_test_role()
    valid_until = datetime.now(timezone.utc) + timedelta(minutes=10)
    with test_engine.connect() as conn:
        sync_roles(conn, role_name, grants=(
            Login(valid_until=valid_until, password='password'),
            DatabaseConnect(TEST_DATABASE_NAME),
            SchemaUsage(schema_name),
            TableSelect(schema_name, table_name),
        ))

    engine = sa.create_engine(f'{engine_type}://{role_name}:password@127.0.0.1:5432/{TEST_DATABASE_NAME}', **engine_future)
    with engine.connect() as conn:
        assert conn.execute(sa.text(f"SELECT count(*) FROM {schema_name}.{table_name}")).fetchall()[0][0] == 0
