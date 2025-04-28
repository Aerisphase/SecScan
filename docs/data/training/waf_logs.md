# WAF Logs

## Обзор
Файл `waf_logs.json` содержит логи Web Application Firewall (WAF), включая информацию о заблокированных атаках, подозрительных запросах и статистике безопасности.

## Структура данных

Данные хранятся в формате JSON и имеют следующую структуру:

```json
{
    "logs": [                    # Записи логов
        {
            "timestamp": str,     # Временная метка
            "source_ip": str,     # IP-адрес источника
            "request": {          # Информация о запросе
                "method": str,    # HTTP метод
                "url": str,       # URL запроса
                "headers": Dict,  # HTTP заголовки
                "body": str       # Тело запроса
            },
            "action": str,        # Действие WAF
            "rule_id": str,       # Идентификатор правила
            "rule_name": str,     # Название правила
            "severity": str,      # Уровень серьезности
            "details": {          # Детали события
                "matched_pattern": str,  # Совпавший паттерн
                "category": str,         # Категория атаки
                "description": str       # Описание
            }
        }
    ],
    "statistics": {              # Статистика
        "total_requests": int,   # Всего запросов
        "blocked_requests": int, # Заблокировано
        "by_category": {         # По категориям
            "sql_injection": int,
            "xss": int,
            "rce": int,
            "path_traversal": int
        },
        "by_severity": {         # По уровням серьезности
            "critical": int,
            "high": int,
            "medium": int,
            "low": int
        }
    }
}
```

## Категории атак

### SQL Injection
- UNION-based
- Error-based
- Time-based
- Boolean-based

### XSS
- Reflected
- Stored
- DOM-based
- Blind

### Remote Code Execution
- Command Injection
- File Upload
- Deserialization
- Template Injection

### Path Traversal
- Directory Traversal
- File Inclusion
- LFI/RFI
- Path Manipulation

## Использование данных

### Для анализа логов
```python
import json
from datetime import datetime

with open('waf_logs.json', 'r') as f:
    data = json.load(f)
    
# Анализ статистики
print(f"Всего запросов: {data['statistics']['total_requests']}")
print(f"Заблокировано: {data['statistics']['blocked_requests']}")

# Анализ по категориям
for category, count in data['statistics']['by_category'].items():
    print(f"{category}: {count}")
```

### Для мониторинга
```python
def analyze_logs(data, time_period='1h'):
    current_time = datetime.now()
    recent_logs = [
        log for log in data['logs']
        if (current_time - datetime.fromisoformat(log['timestamp'])).total_seconds() <= 3600
    ]
    
    return {
        'total': len(recent_logs),
        'by_severity': count_by_severity(recent_logs),
        'by_category': count_by_category(recent_logs)
    }
```

## Особенности данных

1. **Структура логов**
   - Временные метки
   - Информация о запросах
   - Действия WAF
   - Детали событий

2. **Классификация**
   - Категории атак
   - Уровни серьезности
   - Типы правил
   - Источники атак

3. **Статистика**
   - Общие показатели
   - Распределение по категориям
   - Распределение по серьезности
   - Тренды атак

## Рекомендации по использованию

1. Регулярно анализируйте логи
2. Настройте алерты для критических событий
3. Используйте для настройки правил WAF
4. Отслеживайте тренды атак
5. Интегрируйте с SIEM системами 