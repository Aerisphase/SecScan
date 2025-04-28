# Preprocessed Data

## Обзор
Файл `preprocessed_data.json` содержит предобработанные данные для обучения моделей машинного обучения. Данные представляют собой структурированную информацию о различных типах уязвимостей и их характеристиках.

## Структура данных

Данные хранятся в формате JSON и имеют следующую структуру:

```json
{
    "vulnerabilities": [
        {
            "type": str,          # Тип уязвимости
            "severity": str,      # Уровень серьезности
            "description": str,   # Описание уязвимости
            "payloads": [str],    # Примеры payloads
            "patterns": [str],    # Паттерны для обнаружения
            "context": str,       # Контекст уязвимости
            "mitigation": str,    # Рекомендации по исправлению
            "metadata": {
                "source": str,    # Источник данных
                "timestamp": str, # Время создания
                "version": str    # Версия данных
            }
        }
    ]
}
```

## Типы уязвимостей

Данные включают информацию о следующих типах уязвимостей:
- SQL Injection
- XSS (Cross-Site Scripting)
- CSRF (Cross-Site Request Forgery)
- Path Traversal
- Command Injection
- File Inclusion
- XXE (XML External Entity)
- SSRF (Server-Side Request Forgery)

## Уровни серьезности

Уязвимости классифицируются по следующим уровням серьезности:
- Critical
- High
- Medium
- Low
- Info

## Использование данных

### Для обучения моделей
```python
import json

with open('preprocessed_data.json', 'r') as f:
    data = json.load(f)
    
# Использование данных для обучения
for vuln in data['vulnerabilities']:
    # Обработка данных
    pass
```

### Для валидации
```python
def validate_data(data):
    required_fields = ['type', 'severity', 'description', 'payloads']
    for vuln in data['vulnerabilities']:
        for field in required_fields:
            if field not in vuln:
                raise ValueError(f"Missing required field: {field}")
```

## Особенности данных

1. **Предобработка**
   - Нормализация текста
   - Удаление дубликатов
   - Валидация форматов
   - Кодирование категориальных признаков

2. **Качество данных**
   - Проверка на полноту
   - Валидация значений
   - Устранение шума
   - Балансировка классов

3. **Метаданные**
   - Информация об источнике
   - Временные метки
   - Версии данных
   - Статистика распределения

## Рекомендации по использованию

1. Проверяйте версию данных перед использованием
2. Учитывайте контекст уязвимостей
3. Используйте рекомендуемые mitigation
4. Обновляйте данные регулярно
5. Валидируйте данные перед использованием 