# SecScan - Web Vulnerability Scanner

SecScan is a powerful web vulnerability scanner designed to help security professionals and developers identify and fix security issues in web applications. It combines traditional scanning techniques with modern approaches to provide accurate and efficient security testing.

## 🚀 Features

- **Comprehensive Scanning**: Detect OWASP Top 10 vulnerabilities including SQL Injection, XSS, CSRF, and more
- **Modern Interface**: Clean, intuitive web interface with real-time scanning feedback
- **Advanced Configuration**: Customize scan parameters for optimal results
- **Detailed Reporting**: Export scan results in multiple formats
- **Real-time Terminal**: Monitor scan progress with a built-in terminal interface

## 📋 Requirements

- Python 3.8 or higher
- pip (Python package manager)
- Modern web browser (Chrome, Firefox, Edge recommended)

## 🛠️ Installation

1. Clone the repository:
```bash
git clone https://github.com/Aerisphase/SecScan.git
cd SecScan
```

2. Create and activate a virtual environment:

**Windows:**
```cmd
python -m venv venv
venv\Scripts\activate
```

**Linux/macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## ⚙️ Configuration

1. Create a `.env` file in the project root with the following variables:
```bash
SECSCAN_API_KEY=your_api_key_here
SERVER_HOST=localhost
SERVER_PORT=8000
SSL_CERT_PATH=path/to/your/cert.pem
SSL_KEY_PATH=path/to/your/key.pem
```

## 🏃‍♂️ Quick Start

1. Start the server:
```bash
cd src/server
python server.py
```

2. Access the web interface:
```
https://localhost:8000/static/index.html
```

## 🔧 Usage

### Web Interface
1. Open the web interface in your browser
2. Enter the target URL
3. Configure scan settings:
   - Scan Type (Fast/Full)
   - Maximum Pages
   - Request Delay
   - Custom User-Agent
4. Click "Start Scan"
5. Monitor progress in the terminal
6. View and export results

### Command Line
```bash
python scanner.py --target https://example.com \
                 --scan-type full \
                 --delay 2.0 \
                 --max-pages 50 \
                 --verify-ssl \
                 --proxy http://proxy:8080 \
                 --auth user:pass \
                 --max-retries 5
```

## 📊 Scan Types

- **Fast Scan**: Quick analysis focusing on common vulnerabilities
- **Full Scan**: Comprehensive analysis including advanced checks

## 🔍 Supported Vulnerabilities

- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Server-Side Request Forgery (SSRF)
- XML External Entity (XXE)
- Security Misconfigurations
- Insecure Direct Object References (IDOR)
- Broken Authentication
- Sensitive Data Exposure
- Using Components with Known Vulnerabilities

## 🛡️ Security Features

- Rate limiting to prevent server overload
- Configurable retry mechanism
- SSL/TLS verification
- Proxy support
- Authentication support
- URL validation and sanitization
- Security header analysis

## 📝 Output Formats

- HTML Report
- JSON Export
- Terminal Output
- Real-time Logs

## 1. Назначение проекта
Разработка автоматизированного сканера уязвимостей с элементами искусственного интеллекта (AI/ML) для:
- Быстрого и точного поиска уязвимостей в веб-приложениях
- Уменьшения количества ложных срабатываний (False Positives)
- Автоматической генерации рекомендаций по исправлению

### 1.1. Цели разработки
Создание интеллектуального сканера уязвимостей нового поколения, который:
- Автоматизирует 90% рутинных задач пентестера
- Снижает количество ложных срабатываний в 3-5 раз по сравнению с существующими решениями
- Предоставляет готовые решения для исправления уязвимостей

### 1.2. Решаемые проблемы

| Проблема                  | Традиционные решения      | Наш подход                          |
|---------------------------|---------------------------|-------------------------------------|
| Высокий процент ложных срабатываний | Ручная верификация       | ML-фильтрация с точностью >95%      |
| Длительное время сканирования      | Линейные проверки        | Параллельный анализ + приоритезация |
| Сложность интерпретации результатов | Текстовые отчеты         | Интерактивные рекомендации с кодом  |

### 1.3. Целевая аудитория
**a) Пентестеры**  
Профессиональные специалисты по безопасности  
*Выгода: экономия 40-60% времени на проверках*

**b) Разработчики**  
Веб-программисты, проверяющие свой код  
*Выгода: примеры исправлений для популярных фреймворков*

**c) DevOps-инженеры**  
*Выгода: интеграция в CI/CD pipelines*

### 1.4. Ключевые преимущества
**Для бизнеса**
- Снижение затрат на аудит безопасности
- Соответствие требованиям GDPR, PCI DSS

**Технические особенности**
- Поддержка 20+ типов уязвимостей (OWASP Top 10 + API)
- Экспорт отчетов в HTML, PDF, JSON

### 1.5. Ожидаемые результаты
**Количественные**  
🔹 Обнаружение ≥95% уязвимостей из OWASP Top 10  
🔹 Среднее время сканирования: ≤15 мин (сайт на 500 страниц)  

**Качественные**  
🔹 Интуитивно понятный интерфейс (CLI + Web)  
🔹 Модульная архитектура для легкого расширения  

### 1.6. Ограничения
- Не заменяет полноценный ручной пентест
- Требует базовых знаний о веб-безопасности
- Оптимизирован для современных технологий


---

## 2. Сравнение с конкурентами

| Критерий          | Обычные сканеры               | Наш сканер                          |
|--------------------|-------------------------------|-------------------------------------|
| Автоматизация      | Требуют ручной настройки      | Полностью автономный анализ + адаптация к WAF |
| AI/ML              | Нет или слабая интеграция     | ML-фильтрация ложных срабатываний, предсказание 0-day |
| Исправления        | Только отчёт                  | Генерация патчей / правил для WAF   |
| Интеграции         | Часто ограничены              | CI/CD, IDE, мессенджеры (Telegram/Slack) |
| Цена               | Дорого (Burp Suite Pro)       | Бесплатный core + платные фичи      |

---

## 3. Основные функции
### 3.1 Ядро сканирования
- Проверка на OWASP Top 10 (SQLi, XSS, CSRF, RCE и др.)
- Поддержка REST API, GraphQL, WebSockets
- Обход CAPTCHA и WAF (Cloudflare, ModSecurity)

### 3.2 AI-модули
- Классификация угроз (ML-модель для определения реальных уязвимостей)
- Контекстный анализ (приоритезация рисков: платежи > блог)
- Генерация payloads (автоподбор обходных техник для WAF)

### 3.3 Roadmap
SSRF (Server-Side Request Forgery)

XXE (XML External Entity)

IDOR (Insecure Direct Object References)

File Upload Vulnerabilities

Command Injection

Path Traversal

Broken Authentication

Sensitive Data Exposure

Security Misconfiguration

Using Components with Known Vulnerabilities

Insufficient Logging & Monitoring

To train AI:

python src/ai/training/train.py





