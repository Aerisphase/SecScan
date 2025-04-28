# Модуль HTTP Client

## Обзор
Модуль `http_client.py` предоставляет удобный интерфейс для выполнения HTTP-запросов с поддержкой повторных попыток, ограничением частоты запросов и обработкой ошибок.

## Основные компоненты

### Класс HttpClient
Основной класс для работы с HTTP-запросами.

#### Методы:
- `__init__(self, verify_ssl: bool = True, timeout: int = 5, max_retries: int = 2, rate_limit: float = 0.5, proxy: Optional[str] = None, auth: Optional[Dict[str, str]] = None)`
  - Инициализация HTTP-клиента
  - Параметры:
    - `verify_ssl`: Проверка SSL-сертификатов
    - `timeout`: Таймаут запросов в секундах
    - `max_retries`: Максимальное количество повторных попыток
    - `rate_limit`: Минимальный интервал между запросами
    - `proxy`: URL прокси-сервера
    - `auth`: Учетные данные для базовой аутентификации

- `_rate_limit(self)`
  - Реализация ограничения частоты запросов
  - Приостанавливает выполнение, если прошло недостаточно времени с последнего запроса

- `_make_request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]`
  - Выполнение HTTP-запроса с обработкой ошибок
  - Параметры:
    - `method`: HTTP-метод (GET, POST и т.д.)
    - `url`: URL для запроса
    - `**kwargs`: Дополнительные параметры запроса
  - Возвращает объект Response или None в случае ошибки

- `get(self, url: str, **kwargs) -> Optional[requests.Response]`
  - Выполнение GET-запроса
  - Параметры:
    - `url`: URL для запроса
    - `**kwargs`: Дополнительные параметры запроса

- `post(self, url: str, data: Optional[Dict[str, Any]] = None, **kwargs) -> Optional[requests.Response]`
  - Выполнение POST-запроса
  - Параметры:
    - `url`: URL для запроса
    - `data`: Данные для отправки
    - `**kwargs`: Дополнительные параметры запроса

## Особенности реализации

1. **Повторные попытки**
   - Автоматические повторные попытки при ошибках сервера (500, 502, 503, 504)
   - Экспоненциальная задержка между попытками
   - Настраиваемое максимальное количество попыток

2. **Ограничение частоты запросов**
   - Настраиваемый интервал между запросами
   - Предотвращение блокировки IP-адреса

3. **Обработка ошибок**
   - Логирование ошибок
   - Возврат None вместо исключений
   - Поддержка различных типов ошибок

4. **Безопасность**
   - Поддержка SSL/TLS
   - Базовая аутентификация
   - Прокси-серверы

## Пример использования

```python
from core.http_client import HttpClient

# Создание клиента
client = HttpClient(
    verify_ssl=True,
    timeout=10,
    max_retries=3,
    rate_limit=1.0,
    proxy='http://proxy.example.com:8080',
    auth={'username': 'user', 'password': 'pass'}
)

# GET-запрос
response = client.get('https://example.com')
if response:
    print(f"Status: {response.status_code}")
    print(f"Content: {response.text[:100]}")

# POST-запрос
data = {'username': 'test', 'password': 'test123'}
response = client.post('https://example.com/login', data=data)
if response:
    print(f"Status: {response.status_code}")
```

## Рекомендации по использованию

1. Настройте параметры в зависимости от целевого сайта:
   - `rate_limit`: Увеличьте для сайтов с строгими ограничениями
   - `timeout`: Увеличьте для медленных сайтов
   - `max_retries`: Увеличьте для нестабильных соединений

2. Используйте прокси для распределения нагрузки

3. Настройте User-Agent и другие заголовки для имитации реального браузера

4. Обрабатывайте случаи, когда запрос возвращает None (ошибка)

5. Используйте контекстный менеджер для автоматического закрытия соединений 