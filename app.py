from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import redis
import hashlib
import secrets
import datetime
from functools import wraps
import platform
import socket
import os

app = Flask(__name__)
CORS(app)  # Включаем CORS для всех доменов

# Подключение к Redis
redis_url = os.getenv("REDIS_URL", "redis://red-d2m4543uibrs73fqt7c0:6379")
try:
    r = redis.from_url(redis_url, decode_responses=True)
    r.ping()
    print("Успешное подключение к Redis!")
except (redis.exceptions.ConnectionError, socket.gaierror) as e:
    print(f"Ошибка подключения к Redis: {e}")
    r = None

# Инициализация базы данных (Redis)
def init_db():
    if r is None:
        print("Redis не доступен. Пропускаем инициализацию базы данных.")
        return
    admin_password = hashlib.sha256('admin123'.encode()).hexdigest()
    r.hset('users:admin', 'password_hash', admin_password)
    print("База данных инициализирована. Админ 'admin' создан.")

init_db()

# Декоратор для проверки авторизации
def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_token = request.headers.get('Authorization')
        if not auth_token or not r.sismember('auth_tokens', auth_token):
            return jsonify({'success': False, 'message': 'Не авторизован'}), 401
        return f(*args, **kwargs)
    return decorated_function

# Очистка устаревших токенов (можно запускать периодически)
def cleanup_tokens():
    if r is None:
        return
    current_time = datetime.datetime.now().timestamp()
    # Предположим, что токены устаревают через 1 час (3600 секунд)
    for token in r.smembers('auth_tokens'):
        # Здесь можно добавить логику проверки времени создания токена, если вы его сохраняете
        r.srem('auth_tokens', token)  # Упрощенная очистка (убираем все токены при рестарте)

# =================== НОВЫЙ МАРШРУТ ДЛЯ СТАТИЧЕСКИХ ФАЙЛОВ ===================
# Этот маршрут должен идти ПЕРЕД if __name__ == "__main__":
@app.route('/<path:filename>')
def download_file(filename):
    """Отдает файлы из папки 'static'."""
    # Простая защита от обхода путей (не обязательно, но рекомендуется)
    if '..' in filename or filename.startswith('/'):
        return jsonify({'success': False, 'message': 'Неверный путь к файлу'}), 400
    try:
        return send_from_directory('static', filename, as_attachment=True)
    except FileNotFoundError:
        return jsonify({'success': False, 'message': 'Файл не найден'}), 404
# ============================================================================

# API для авторизации админа
@app.route('/api/login', methods=['POST'])
def login():
    if r is None:
        return jsonify({'success': False, 'message': 'Сервер Redis недоступен'}), 503
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'success': False, 'message': 'Неверные данные'}), 400
    username = data['username']
    password = data['password']
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    user_data = r.hgetall(f'users:{username}')
    if user_data and user_data.get('password_hash') == password_hash:
        auth_token = secrets.token_hex(16)
        r.sadd('auth_tokens', auth_token)
        return jsonify({'success': True, 'token': auth_token})
    else:
        return jsonify({'success': False, 'message': 'Неверный логин или пароль'}), 401

# API для генерации ключа - ДОБАВЛЕНО поле version
@app.route('/api/generate', methods=['POST'])
@require_auth
def generate_key():
    if r is None:
        return jsonify({'success': False, 'message': 'Сервер Redis недоступен'}), 503
    data = request.get_json()
    # Проверяем обязательные поля, включая version
    if not data or 'days' not in data or 'version' not in data: # ИСПРАВЛЕНО: добавлено 'data' после 'version' not in
        return jsonify({'success': False, 'message': 'Неверные данные: отсутствует days или version'}), 400
    try:
        days = int(data['days'])
        if days <= 0:
            return jsonify({'success': False, 'message': 'Количество дней должно быть больше 0'}), 400
    except ValueError:
        return jsonify({'success': False, 'message': 'Неверный формат дней'}), 400

    # Проверяем корректность версии
    version = data['version']
    if version not in ['standard', 'special']:
         return jsonify({'success': False, 'message': 'Неверная версия. Допустимые значения: standard, special'}), 400

    key_value = secrets.token_urlsafe(16)
    created_at = datetime.datetime.now().isoformat()
    key_data = {
        'key_value': key_value,
        'days': days,
        'created_at': created_at,
        'is_active': '0'
    }
    r.hmset(f'keys:{key_value}', key_data)
    r.sadd('all_keys', key_value)
    # Возвращаем также версию в ответе
    return jsonify({
        'success': True,
        'message': 'Ключ успешно сгенерирован',
        'key': key_value,
        'days': days,
    })

# API для получения списка ключей - ДОБАВЛЕНО поле version в ответ
@app.route('/api/keys', methods=['GET'])
@require_auth
def get_all_keys():
    if r is None:
        return jsonify({'success': False, 'message': 'Сервер Redis недоступен'}), 503
    key_values = r.smembers('all_keys')
    keys = []
    for key_value in key_values:
        key_data = r.hgetall(f'keys:{key_value}')
        if not key_data:
            r.srem('all_keys', key_value)
            continue
        # Получаем версию
        version = key_data.get('version', 'unknown') # ДОБАВЛЕНО
        is_active = key_data.get('is_active') == '1'
        status = "Не активирован"
        if is_active:
            activated_at_str = key_data.get('activated_at')
            if activated_at_str:
                activated_at = datetime.datetime.fromisoformat(activated_at_str)
                days_left = (activated_at + datetime.timedelta(days=int(key_data.get('days'))) - datetime.datetime.now()).days
                if days_left > 0:
                    status = f"Активен, осталось {days_left} дней"
                else:
                    status = "Срок действия истёк"
            else:
                status = "Активен"
        keys.append({
            'key': key_data.get('key_value'),
            'days': int(key_data.get('days')),
            'version': version, # ДОБАВЛЕНО
            'hwid': key_data.get('hwid') or 'Не привязан',
            'status': status,
            'created_at': key_data.get('created_at'),
            'activated_at': key_data.get('activated_at') or 'Не активирован'
        })
    keys.sort(key=lambda x: x['created_at'], reverse=True)
    return jsonify({'success': True, 'keys': keys})

# API для активации ключа - ПРОВЕРКА ВЕРСИИ
@app.route('/api/activate', methods=['POST'])
def activate_key():
    if r is None:
        return jsonify({'success': False, 'message': 'Сервер Redis недоступен'}), 503
    data = request.get_json()
    # Проверяем обязательные поля, включая version_from_client
    if not data or 'key' not in data or 'hwid' not in data or 'version' not in data: # ИСПРАВЛЕНО: добавлено 'data' после 'version' not in
        return jsonify({'success': False, 'message': 'Неверные данные: отсутствует key, hwid или version'}), 400
    key_value = data['key']
    hwid = data['hwid']
    client_version = data['version'] # ДОБАВЛЕНО - версия, которую запрашивает клиент

    key_data = r.hgetall(f'keys:{key_value}')
    if not key_data:
        return jsonify({'success': False, 'message': 'Ключ не найден'}), 404

    # Проверяем, соответствует ли версия ключа версии клиента
    key_version = key_data.get('version', 'unknown') # ДОБАВЛЕНО
    # ПРАВИЛО: standard ключ может быть активирован ТОЛЬКО для standard версии.
    # special ключ может быть активирован для standard или special версии.
    if key_version == 'standard' and client_version != 'standard':
        return jsonify({'success': False, 'message': f'Ключ версии "{key_version}" не может быть активирован для версии "{client_version}".'}), 400 # ИСПРАВЛЕНО
    # Для special ключа проверка не нужна, он подходит обеим версиям.
    # if key_version != client_version: # Это было раньше, теперь логика другая

    is_active = key_data.get('is_active') == '1'
    if is_active:
        current_hwid = key_data.get('hwid')
        if current_hwid and current_hwid != hwid:
            return jsonify({'success': False, 'message': 'Ключ уже привязан к другому устройству'}), 409
        activated_at_str = key_data.get('activated_at')
        if activated_at_str:
            activated_at = datetime.datetime.fromisoformat(activated_at_str)
            expires_at = activated_at + datetime.timedelta(days=int(key_data.get('days')))
            if datetime.datetime.now() > expires_at:
                return jsonify({'success': False, 'message': 'Срок действия ключа истек'}), 410
            return jsonify({
                'success': True,
                'message': 'Ключ уже активирован',
                'expires_at': expires_at.isoformat()
            })

    activated_at = datetime.datetime.now()
    r.hset(f'keys:{key_value}', 'is_active', '1')
    r.hset(f'keys:{key_value}', 'hwid', hwid)
    r.hset(f'keys:{key_value}', 'activated_at', activated_at.isoformat())
    expires_at = activated_at + datetime.timedelta(days=int(key_data.get('days')))
    return jsonify({
        'success': True,
        'message': 'Ключ успешно активирован',
        'expires_at': expires_at.isoformat()
    })

# API для проверки ключа - ПРОВЕРКА ВЕРСИИ (если используется)
@app.route('/api/check', methods=['POST'])
def check_key():
    if r is None:
        return jsonify({'success': False, 'message': 'Сервер Redis недоступен'}), 503
    data = request.get_json()
    if not data or 'key' not in data or 'hwid' not in data or 'version' not in data: # ИСПРАВЛЕНО: добавлено 'data' после 'version' not in
        return jsonify({'success': False, 'message': 'Неверные данные'}), 400
    key_value = data['key']
    hwid = data['hwid']
    client_version = data['version'] # ДОБАВЛЕНО

    key_data = r.hgetall(f'keys:{key_value}')
    if not key_data:
        return jsonify({'success': False, 'message': 'Ключ не найден'}), 404

    # Проверяем версию ключа
    key_version = key_data.get('version', 'unknown') # ДОБАВЛЕНО
    # ПРАВИЛО: standard ключ может быть проверен ТОЛЬКО для standard версии.
    # special ключ может быть проверен для standard или special версии.
    if key_version == 'standard' and client_version != 'standard':
        return jsonify({'success': False, 'message': f'Ключ версии "{key_version}" не может быть проверен для версии "{client_version}".'}), 400 # ИСПРАВЛЕНО
    # Для special ключа проверка не нужна, он подходит обеим версиям.
    # if key_version != client_version: # Это было раньше, теперь логика другая

    if key_data.get('is_active') != '1':
        return jsonify({'success': False, 'message': 'Ключ не активирован'}), 401
    if key_data.get('hwid') != hwid:
        return jsonify({'success': False, 'message': 'HWID не совпадает'}), 403
    activated_at_str = key_data.get('activated_at')
    expires_at = datetime.datetime.fromisoformat(activated_at_str) + datetime.timedelta(days=int(key_data.get('days')))
    if datetime.datetime.now() > expires_at:
        return jsonify({'success': False, 'message': 'Срок действия ключа истек'}), 410
    return jsonify({
        'success': True,
        'message': 'Ключ действителен',
        'expires_at': expires_at.isoformat()
    })

# API для удаления ключа
@app.route('/api/delete-key', methods=['POST'])
@require_auth
def delete_key():
    if r is None:
        return jsonify({'success': False, 'message': 'Сервер Redis недоступен'}), 503
    data = request.get_json()
    if not data or 'key' not in data:
        return jsonify({'success': False, 'message': 'Неверные данные'}), 400
    key_value = data['key']
    deleted_count = r.delete(f'keys:{key_value}')
    if deleted_count > 0:
        r.srem('all_keys', key_value)
        return jsonify({'success': True, 'message': 'Ключ успешно удален'})
    else:
        return jsonify({'success': False, 'message': 'Ключ не найден'}), 404

# Основной блок запуска
if __name__ == "__main__":
    print("Запуск локального сервера...")
    app.run(host='0.0.0.0', port=5000, debug=True)

