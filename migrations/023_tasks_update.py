# 023_tasks_update.py


def migrate(migrator, database, fake=False, **kwargs):

    migrator.sql("""ALTER TABLE tasks
        ADD COLUMN action text not null default 'None'
    """)