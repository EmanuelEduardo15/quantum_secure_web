from flask import Flask, render_template, request, redirect, url_for, flash
import threading, queue, sqlite3, uuid
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

app = Flask(__name__)
app.secret_key = 'substitua_por_uma_chave_segura'

# Fila e resultados para geração async
tasks = queue.Queue()
results = {}

# Worker que gera chaves 2048 bits em background
def key_worker():
    conn = sqlite3.connect('keys_async.db')
    conn.execute('CREATE TABLE IF NOT EXISTS async_keys (id TEXT PRIMARY KEY, public TEXT, private TEXT)')
    conn.commit()
    while True:
        tid = tasks.get()
        key = RSA.generate(2048)
        pub = key.publickey().export_key().decode()
        priv= key.export_key().decode()
        conn.execute('INSERT OR REPLACE INTO async_keys (id,public,private) VALUES (?,?,?)',
                     (tid, pub, priv))
        conn.commit()
        results[tid] = {'public': pub, 'private': priv}
        tasks.task_done()

threading.Thread(target=key_worker, daemon=True).start()

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Inicia geração de par de chaves
        tid = str(uuid.uuid4())
        tasks.put(tid)
        flash(f"Gerando chave... seu ID de tarefa é {tid}", "info")
        return redirect(url_for('status', task_id=tid))
    return render_template('index.html')

@app.route('/status/<task_id>')
def status(task_id):
    if task_id in results:
        data = results.pop(task_id)
        # Armazena em sessão ou db; para demo, passamos direto
        return render_template('result.html',
                               public_key=data['public'],
                               private_key=data['private'],
                               task_id=task_id)
    return render_template('status.html', task_id=task_id)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    pub_key = request.form['public_key']
    message = request.form['message']
    key = RSA.import_key(pub_key.encode())
    cipher = PKCS1_OAEP.new(key)
    ct = cipher.encrypt(message.encode())
    b64 = base64.b64encode(ct).decode()
    return render_template('result.html', ciphertext=b64, public_key=pub_key)

@app.route('/decrypt', methods=['POST'])
def decrypt():
    priv_key = request.form['private_key']
    ciphertext = request.form['ciphertext']
    key = RSA.import_key(priv_key.encode())
    cipher = PKCS1_OAEP.new(key)
    pt = cipher.decrypt(base64.b64decode(ciphertext.encode())).decode()
    return render_template('result.html', message=pt, private_key=priv_key)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
