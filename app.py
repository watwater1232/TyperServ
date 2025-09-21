from flask import Flask, request, jsonify
import redis
import hashlib
import secrets
import datetime
from functools import wraps
import platform
import socket
import os

app = Flask(__name__)

# Подключение к Redis
# Используем переменную окружения REDIS_URL, которую предоставляет Render
redis_url = os.getenv("REDIS_URL", "redis://red-d2m4543uibrs73fqt7c0:6379")
try:
    r = redis.from_url(redis_url, decode_responses=True)
    # Попробуйте выполнить простую команду, чтобы проверить соединение
    r.ping()
    print("Успешное подключение к Redis!")
except (redis.exceptions.ConnectionError, socket.gaierror) as e:
    print(f"Ошибка подключения к Redis: {e}")
    # Вы можете захотеть, чтобы приложение не запускалось, если подключение не удалось
    # Или использовать mock-объект для тестирования
    r = None

# Инициализация базы данных (Redis)
def init_db():
    if r is None:
        print("Redis не доступен. Пропускаем инициализацию базы данных.")
        return
        
    # Создаем админа по умолчанию (admin/admin123)
    admin_password = hashlib.sha256('admin123'.encode()).hexdigest()
    # Используем HASH для хранения данных пользователя
    r.hset('users:admin', 'password_hash', admin_password)
    r.hset('users:admin', 'is_admin', 'True')
    print("Redis DB initialized.")

# Генерация ключа
def generate_key():
    return secrets.token_hex(16).upper()

# Декоратор для проверки авторизации админа
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'success': False, 'message': 'Authorization header is missing or invalid'}), 401
        
        token = auth_header.split(' ')[1]
        
        # Здесь вы можете реализовать свою логику проверки токена
        # Для простоты, мы будем использовать сессию или JWT
        # Сейчас мы просто проверяем, что пользователь 'admin' существует
        if not r.exists('users:admin'):
             return jsonify({'success': False, 'message': 'Admin not found'}), 401
        
        return f(*args, **kwargs)
    return decorated_function

# API для генерации ключа (админка)
@app.route('/api/generate_key', methods=['POST'])
@admin_required
def generate_key_api():
    if r is None:
        return jsonify({'success': False, 'message': 'Сервер Redis недоступен'}), 503
        
    data = request.get_json()
    
    if not data or 'days' not in data:
        return jsonify({'success': False, 'message': 'Укажите количество дней'})
    
    try:
        days = int(data['days'])
        if days <= 0:
            return jsonify({'success': False, 'message': 'Количество дней должно быть больше 0'})
    except ValueError:
        return jsonify({'success': False, 'message': 'Неверный формат дней'})
    
    key = generate_key()
    
    # Используем SET для проверки уникальности ключа
    while r.sismember('unique_keys', key):
        key = generate_key()

    # Сохраняем ключ в Redis HASH
    key_data = {
        'key_value': key,
        'days': days,
        'is_active': 'True',
        'created_at': datetime.datetime.now().isoformat()
    }
    r.hmset(f'key:{key}', key_data)
    r.sadd('unique_keys', key)
    
    return jsonify({'success': True, 'key': key, 'days': days})

# API для активации ключа (лоадер)
@app.route('/api/activate_key', methods=['POST'])
def activate_key():
    if r is None:
        return jsonify({'success': False, 'message': 'Сервер Redis недоступен'}), 503
        
    data = request.get_json()
    
    if not data or 'key' not in data or 'hwid' not in data:
        return jsonify({'success': False, 'message': 'Неверные данные'})
    
    key = data['key'].strip().upper()
    hwid = data['hwid'].strip()
    
    # Проверяем, существует ли ключ
    if not r.exists(f'key:{key}'):
        return jsonify({'success': False, 'message': 'Ключ не найден или деактивирован'})
    
    key_data = r.hgetall(f'key:{key}')
    
    is_active = key_data.get('is_active') == 'True'
    if not is_active:
        return jsonify({'success': False, 'message': 'Ключ не найден или деактивирован'})

    existing_hwid = key_data.get('hwid')
    activated_at = key_data.get('activated_at')
    expires_at = key_data.get('expires_at')

    # Если ключ уже активирован
    if activated_at:
        if existing_hwid != hwid:
            return jsonify({'success': False, 'message': 'Ключ уже активирован на другом компьютере'})
        
        # Проверяем срок действия
        expires_datetime = datetime.datetime.fromisoformat(expires_at)
        if datetime.datetime.now() > expires_datetime:
            return jsonify({'success': False, 'message': 'Срок действия ключа истек'})
        
        days_remaining = (expires_datetime - datetime.datetime.now()).days
        return jsonify({
            'success': True, 
            'message': 'Ключ уже активирован на этом компьютере',
            'expires_at': expires_at,
            'days_remaining': days_remaining
        })
    
    # Активируем ключ
    now = datetime.datetime.now()
    days = int(key_data.get('days'))
    expires = now + datetime.timedelta(days=days)
    
    r.hset(f'key:{key}', 'hwid', hwid)
    r.hset(f'key:{key}', 'activated_at', now.isoformat())
    r.hset(f'key:{key}', 'expires_at', expires.isoformat())
    
    # Устанавливаем TTL для автоматического удаления ключа
    r.expireat(f'key:{key}', expires)
    
    return jsonify({
        'success': True, 
        'message': 'Ключ успешно активирован',
        'expires_at': expires.isoformat(),
        'days_remaining': days
    })

# API для проверки статуса ключа
@app.route('/api/check_key', methods=['POST'])
def check_key():
    if r is None:
        return jsonify({'success': False, 'message': 'Сервер Redis недоступен'}), 503
        
    data = request.get_json()
    
    if not data or 'key' not in data or 'hwid' not in data:
        return jsonify({'success': False, 'message': 'Неверные данные'})
    
    key = data['key'].strip().upper()
    hwid = data['hwid'].strip()
    
    key_data = r.hgetall(f'key:{key}')

    if not key_data:
        return jsonify({'success': False, 'message': 'Ключ не найден или не активирован на этом компьютере'})
    
    existing_hwid = key_data.get('hwid')
    if existing_hwid != hwid:
        return jsonify({'success': False, 'message': 'Ключ не найден или не активирован на этом компьютере'})

    expires_at = key_data.get('expires_at')
    if not expires_at:
        return jsonify({'success': False, 'message': 'Ключ не активирован'})

    expires_datetime = datetime.datetime.fromisoformat(expires_at)
    if datetime.datetime.now() > expires_datetime:
        return jsonify({'success': False, 'message': 'Срок действия ключа истек'})
    
    days_remaining = (expires_datetime - datetime.datetime.now()).days
    
    return jsonify({
        'success': True,
        'expires_at': expires_at,
        'days_remaining': days_remaining
    })

# API для получения списка ключей (админка)
@app.route('/api/keys', methods=['GET'])
@admin_required
def get_keys():
    if r is None:
        return jsonify({'success': False, 'message': 'Сервер Redis недоступен'}), 503
        
    keys = []
    
    # Получаем все ключи из Redis
    all_keys = r.keys('key:*')
    
    for key_name in all_keys:
        key_data = r.hgetall(key_name)
        
        status = "Не активирован"
        if key_data.get('activated_at'):
            expires_at = key_data.get('expires_at')
            if expires_at:
                expires_datetime = datetime.datetime.fromisoformat(expires_at)
                if datetime.datetime.now() > expires_datetime:
                    status = "Истек"
                else:
                    days_left = (expires_datetime - datetime.datetime.now()).days
                    status = f"Активен ({days_left} дн.)"
            else:
                status = "Активен"
        
        keys.append({
            'key': key_data.get('key_value'),
            'days': key_data.get('days'),
            'hwid': key_data.get('hwid') or 'Не привязан',
            'status': status,
            'created_at': key_data.get('created_at'),
            'activated_at': key_data.get('activated_at') or 'Не активирован'
        })
        
    # Сортируем по дате создания
    keys.sort(key=lambda x: x['created_at'], reverse=True)
    
    return jsonify({'success': True, 'keys': keys})

# API для авторизации админа
@app.route('/api/login', methods=['POST'])
def login():
    if r is None:
        return jsonify({'success': False, 'message': 'Сервер Redis недоступен'}), 503
        
    data = request.get_json()
    
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'success': False, 'message': 'Неверные данные'})
    
    username = data['username']
    password = data['password']
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    user_data = r.hgetall(f'users:{username}')
    
    if user_data and user_data.get('password_hash') == password_hash and user_data.get('is_admin') == 'True':
        return jsonify({'success': True, 'message': 'Успешная авторизация'})
    else:
        return jsonify({'success': False, 'message': 'Неверный логин или пароль'})

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)