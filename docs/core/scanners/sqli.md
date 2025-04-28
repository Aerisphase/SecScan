# Сканер SQL-инъекций

## Обзор
Модуль `sqli.py` реализует функциональность сканирования на наличие уязвимостей SQL-инъекций. Сканер проверяет как параметры URL, так и формы на наличие уязвимостей, используя различные техники и payloads.

## Основные компоненты

### Класс SQLiScanner
Основной класс для сканирования SQL-инъекций.

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

- `_is_vulnerable(self, response_text: str) -> bool`
  - Проверка ответа на наличие признаков уязвимости
  - Параметры:
    - `response_text`: Текст ответа сервера
  - Возвращает True, если найдены признаки уязвимости

- `_extract_error(self, text: str) -> str`
  - Извлечение информации об ошибке из ответа
  - Параметры:
    - `text`: Текст ответа сервера
  - Возвращает описание найденной ошибки

## Payloads и паттерны

### Payloads для тестирования
```python
[
    "'",
    "' OR '1'='1",
    "' OR 1=1 --",
    '" OR "" = "',
    "') OR ('1'='1--",
    "1; DROP TABLE users--",
    "1' WAITFOR DELAY '0:0:10'--",
    "1 OR 1=1",
    "1' UNION SELECT NULL--",
    # ... и другие
]
```

### Паттерны ошибок
```python
[
    r"SQL syntax",
    r"MySQL server",
    r"ORA-[0-9]+",
    r"syntax error",
    r"unclosed quotation",
    # ... и другие
]
```

## Формат результатов

Найденные уязвимости возвращаются в виде списка словарей:

```python
{
    'type': 'SQL Injection',
    'url': str,  # URL с уязвимостью
    'payload': str,  # Использованный payload
    'evidence': str,  # Доказательство уязвимости
    'severity': 'critical',  # Уровень серьезности
    'param': str,  # Уязвимый параметр
    'method': str  # Метод запроса (GET/POST)
}
```

## Пример использования

```python
from core.scanners.sqli import SQLiScanner
from core.http_client import HttpClient

# Создание сканера
client = HttpClient()
scanner = SQLiScanner(client)

# Сканирование URL
url = 'https://example.com/search?q=test'
forms = [
    {
        'action': 'https://example.com/login',
        'method': 'POST',
        'fields': ['username', 'password']
    }
]

vulnerabilities = scanner.scan(url, forms)

# Обработка результатов
for vuln in vulnerabilities:
    print(f"Найдена SQL-инъекция в {vuln['url']}")
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
   - Поиск SQL-ошибок в ответах
   - Проверка времени ответа
   - Анализ поведения приложения

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
   - Простые инъекции
   - UNION-based
   - Time-based
   - Error-based

3. Обрабатывайте результаты с учетом контекста:
   - Проверяйте ложные срабатывания
   - Анализируйте уровень серьезности
   - Учитывайте метод внедрения

4. Настройте логирование для отладки:
   - Ошибки сканирования
   - Успешные обнаружения
   - Проблемы с запросами 