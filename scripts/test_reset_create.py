from gui_app import DATA_DIR, PasswordManagerCore, PasswordManagerAdapter, DATA_FILE, HMAC_KEY_FILE, SALT_FILE
import shutil

print('DATA_DIR before:', DATA_DIR)
try:
    shutil.rmtree(DATA_DIR)
    print('removed data dir')
except Exception as e:
    print('no data dir to remove or failed:', e)

pm = PasswordManagerAdapter(PasswordManagerCore())
ok, msg = pm.initialize('Str0ngPass!')
print('initialize:', ok, msg)
print('DATA_DIR exists:', DATA_DIR.exists())
print('DATA_FILE exists:', DATA_FILE.exists())
print('SALT_FILE exists:', SALT_FILE.exists())
print('HMAC key file exists:', HMAC_KEY_FILE.exists())
print('unlock:', pm.unlock('Str0ngPass!'))
