import sqlalchemy as sa


def sync_roles(conn):
    conn.execute(sa.text('SELECT 1'))
