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


@pytest.fixture()
def root_engine():
    return sa.create_engine(f'{engine_type}://postgres@127.0.0.1:5432/', **engine_future)


def test_sync_roles(root_engine):
    with root_engine.connect() as conn:
        for role_name in (uuid.uuid4().hex for _ in range(0, ROLES_PER_TEST)):
            sync_roles(conn, role_name, grants=(
                DatabaseConnect('postgres'),
            ))


def test_sync_role_for_one_user(root_engine):
    role_name = uuid.uuid4().hex
    database_query = f'''
            SELECT has_database_privilege('{role_name}', 'postgres', 'CONNECT') 
        '''
    with root_engine.connect() as conn:
        sync_roles(conn, role_name, grants=(
                DatabaseConnect('postgres'),
            ))
        
        assert conn.execute(sa.text(database_query)).fetchall()[0][0]
        
        
