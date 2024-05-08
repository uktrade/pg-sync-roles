from pg_sync_roles import sync_roles


def test_sync_roles():
    sync_roles()
    assert True
