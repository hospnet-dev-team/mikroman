# 024_sysconfig_update.py

def migrate(migrator, database, fake=False, **kwargs):

    migrator.sql("""INSERT INTO public.sysconfig( key,  value) VALUES ( 'update_mode', 'auto')""")
