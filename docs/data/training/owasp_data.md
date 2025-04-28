# OWASP Data

## Обзор
Файл `owasp_data.json` содержит структурированные данные из OWASP (Open Web Application Security Project), включая информацию о наиболее критичных уязвимостях веб-приложений, паттерны их обнаружения и рекомендации по исправлению.

## Структура данных

Данные хранятся в формате JSON и имеют следующую структуру:

```json
{
    "top_10": [
        {
            "rank": int,          # Ранг в топ-10
            "category": str,      # Категория уязвимости
            "description": str,   # Описание
            "impact": str,        # Возможное воздействие
            "prevalence": str,    # Распространенность
            "detectability": str, # Сложность обнаружения
            "technical_impact": str,  # Техническое воздействие
            "business_impact": str,   # Бизнес-воздействие
            "examples": [str],    # Примеры уязвимостей
            "prevention": [str],  # Методы предотвращения
            "references": [str]   # Ссылки на документацию
        }
    ],
    "testing_guide": {
        "categories": [
            {
                "name": str,      # Название категории
                "tests": [        # Тесты для категории
                    {
                        "id": str,
                        "name": str,
                        "description": str,
                        "steps": [str],
                        "tools": [str]
                    }
                ]
            }
        ]
    },
    "cheat_sheets": [
        {
            "title": str,         # Название шпаргалки
            "content": str,       # Содержание
            "version": str,       # Версия
            "last_updated": str   # Дата обновления
        }
    ]
}
```

## Содержание данных

### OWASP Top 10
- Injection
- Broken Authentication
- Sensitive Data Exposure
- XML External Entities (XXE)
- Broken Access Control
- Security Misconfiguration
- Cross-Site Scripting (XSS)
- Insecure Deserialization
- Using Components with Known Vulnerabilities
- Insufficient Logging & Monitoring

### Руководство по тестированию
- Information Gathering
- Configuration and Deployment Management Testing
- Identity Management Testing
- Authentication Testing
- Authorization Testing
- Session Management Testing
- Input Validation Testing
- Error Handling
- Cryptography
- Business Logic Testing
- Client Side Testing

### Шпаргалки
- XSS Prevention
- SQL Injection Prevention
- Authentication
- Session Management
- Input Validation
- Error Handling
- Secure Headers
- Password Storage

## Использование данных

### Для анализа уязвимостей
```python
import json

with open('owasp_data.json', 'r') as f:
    data = json.load(f)
    
# Анализ топ-10 уязвимостей
for vuln in data['top_10']:
    print(f"Уязвимость #{vuln['rank']}: {vuln['category']}")
    print(f"Описание: {vuln['description']}")
    print(f"Методы предотвращения: {', '.join(vuln['prevention'])}")
```

### Для тестирования
```python
def get_test_steps(category: str, test_id: str) -> List[str]:
    for cat in data['testing_guide']['categories']:
        if cat['name'] == category:
            for test in cat['tests']:
                if test['id'] == test_id:
                    return test['steps']
    return []
```

## Особенности данных

1. **Актуальность**
   - Регулярные обновления
   - Версионирование
   - Отслеживание изменений
   - Проверка достоверности

2. **Структура**
   - Иерархическая организация
   - Связи между элементами
   - Метаданные
   - Ссылки на источники

3. **Использование**
   - Обучение моделей
   - Анализ уязвимостей
   - Разработка тестов
   - Создание отчетов

## Рекомендации по использованию

1. Регулярно обновляйте данные
2. Проверяйте версии документации
3. Используйте актуальные рекомендации
4. Учитывайте контекст применения
5. Следите за изменениями в топ-10 