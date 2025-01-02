# 024_sysconfig_update.py

def migrate(migrator, database, fake=False, **kwargs):

    migrator.sql("""INSERT INTO public.sysconfig( key,  value) VALUES ( 'update_mode', '{"mode": "manual", "update_back": false, "update_front": false}')""")


