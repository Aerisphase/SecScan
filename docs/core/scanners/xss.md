# Сканер XSS

## Обзор
Модуль `xss.py` реализует функциональность сканирования на наличие уязвимостей межсайтового скриптинга (XSS). Сканер проверяет как параметры URL, так и формы на наличие уязвимостей, используя различные payloads и методы обнаружения.

## Основные компоненты

### Класс XSSScanner
Основной класс для сканирования XSS-уязвимостей.

#### Методы:
- `__init__(self, client=None)`
  - Инициализация сканера
  - Параметры:
    - `client`: HTTP-клиент для выполнения запросов

- `scan(self, url: str, forms: Optional[List[Dict]] = None) -> List[Dict]`
  - Основной метод сканирования
  - Параметры:
    - `url`: URL для сканирования
    - `forms`: Список форм для проверки
  - Возвращает список найденных уязвимостей

- `_inject_payload(self, url: str, param: str, payload: str) -> str`
  - Внедрение payload в URL
  - Параметры:
    - `url`: Исходный URL
    - `param`: Параметр для внедрения
    - `payload`: Payload для внедрения
  - Возвращает модифицированный URL

- `_is_vulnerable(self, response_text: str, payload: str) -> bool`
  - Проверка ответа на наличие признаков уязвимости
  - Параметры:
    - `response_text`: Текст ответа сервера
    - `payload`: Использованный payload
  - Возвращает True, если найдены признаки уязвимости

- `_get_evidence(self, response_text: str, payload: str) -> str`
  - Получение доказательства уязвимости
  - Параметры:
    - `response_text`: Текст ответа сервера
    - `payload`: Использованный payload
  - Возвращает описание найденной уязвимости

## Payloads и паттерны

### Payloads для тестирования
```python
[
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "'><script>alert('XSS')</script>",
    "\"><script>alert('XSS')</script>",
    "javascript:alert('XSS')",
    "onmouseover=alert('XSS')",
    "onerror=alert('XSS')",
    "<a href=javascript:alert('XSS')>XSS</a>",
    "<body onload=alert('XSS')>"
]
```

### Паттерны кодирования
```python
[
    r'&lt;script&gt;',
    r'&lt;img',
    r'&lt;svg',
    r'&lt;a',
    r'&lt;body',
    r'&amp;lt;script&amp;gt;',
    r'&amp;lt;img',
    r'&amp;lt;svg',
    r'&amp;lt;a',
    r'&amp;lt;body'
]
```

## Формат результатов

Найденные уязвимости возвращаются в виде списка словарей:

```python
{
    'type': 'XSS',
    'url': str,  # URL с уязвимостью
    'payload': str,  # Использованный payload
    'evidence': str,  # Доказательство уязвимости
    'severity': 'high',  # Уровень серьезности
    'param': str,  # Уязвимый параметр
    'method': str  # Метод запроса (GET/POST)
}
```

## Пример использования

```python
from core.scanners.xss import XSSScanner
from core.http_client import HttpClient

# Создание сканера
client = HttpClient()
scanner = XSSScanner(client)

# Сканирование URL
url = 'https://example.com/search?q=test'
forms = [
    {
        'action': 'https://example.com/comment',
        'method': 'POST',
        'fields': ['comment', 'name']
    }
]

vulnerabilities = scanner.scan(url, forms)

# Обработка результатов
for vuln in vulnerabilities:
    print(f"Найдена XSS-уязвимость в {vuln['url']}")
    print(f"Параметр: {vuln['param']}")
    print(f"Payload: {vuln['payload']}")
    print(f"Доказательство: {vuln['evidence']}")
```

## Особенности реализации

1. **Методы сканирования**
   - Проверка параметров URL
   - Проверка форм (GET и POST)
   - Анализ ответов сервера

2. **Обнаружение уязвимостей**
   - Поиск payload в ответе
   - Проверка кодирования
   - Анализ контекста

3. **Безопасность**
   - Ограничение количества запросов
   - Проверка ответов на ошибки
   - Безопасное внедрение payloads

## Рекомендации по использованию

1. Настройте параметры HTTP-клиента:
   - Таймауты
   - Повторные попытки
   - User-Agent

2. Используйте различные типы payloads:
   - Script-based
   - Event-based
   - Attribute-based
   - JavaScript-based

3. Обрабатывайте результаты с учетом контекста:
   - Проверяйте ложные срабатывания
   - Анализируйте уровень серьезности
   - Учитывайте метод внедрения

4. Настройте логирование для отладки:
   - Ошибки сканирования
   - Успешные обнаружения
   - Проблемы с запросами 