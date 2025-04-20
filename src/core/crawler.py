import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import time
import logging
from typing import Set, Dict, List, Optional
import tldextract
import warnings
import re
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class AdvancedCrawler:
    def __init__(self, 
                 base_url: str,
                 max_pages: int = 20,
                 delay: float = 1.0,
                 user_agent: str = None,
                 verify_ssl: bool = False,
                 debug: bool = False):
        
        self.base_url = base_url  # Базовый URL для сканирования
        self.max_pages = max_pages  # Максимальное количество страниц
        self.delay = delay  # Задержка между запросами (в секундах)
        self.debug = debug  # Режим отладки
        self.visited_urls: Set[str] = set()  # Посещенные URL
        self.queue = []  # Очередь URL для сканирования
        self.session = self._configure_session(user_agent, verify_ssl)  # HTTP-сессия
        self.logger = logging.getLogger('VulnScanner.Crawler')  # Логгер
        
        # Парсинг базового URL
        parsed = urlparse(base_url)
        self.base_domain = parsed.netloc  # Домен сайта
        self.scheme = parsed.scheme  # Протокол (http/https)
        self.base_ext = tldextract.extract(base_url)  # Разобранные компоненты домена
        
        # Настройки безопасности
        self.robots_txt_checked = False  # Проверен ли robots.txt
        self._stats = {  # Статистика сканирования
            'pages_crawled': 0,    # Просмотрено страниц
            'links_found': 0,      # Найдено ссылок
            'forms_found': 0,      # Найдено форм
            'api_endpoints': 0     # Найдено API-эндпоинтов
        }

    def _configure_session(self, user_agent: str, verify_ssl: bool) -> requests.Session:
        """Настройка HTTP-сессии с повторами запросов и параметрами безопасности"""
        session = requests.Session()
        
        # Стратегия повторных попыток
        retries = Retry(
            total=3,               # Максимум 3 попытки
            backoff_factor=1,      # Интервал между попытками
            status_forcelist=[500, 502, 503, 504],  # Коды ошибок для повтора
            allowed_methods=['GET', 'POST']  # Методы для повтора
        )
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))
        
        # Заголовки HTTP-запросов
        session.headers = {
            'User-Agent': user_agent or 'SecScan/2.0 (+https://github.com/Aerisphase/SecScan)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Referer': self.base_url
        }
        
        # Настройки безопасности
        session.verify = verify_ssl  # Проверка SSL-сертификата
        if not verify_ssl:
            warnings.filterwarnings('ignore', message='Unverified HTTPS request')
            
        return session

    def _check_robots_txt(self):
        """Проверка ограничений в файле robots.txt"""
        try:
            robots_url = urljoin(self.base_url, '/robots.txt')
            response = self.session.get(robots_url, timeout=10)
            if response.status_code == 200:
                self.logger.info(f"Найден robots.txt по адресу {robots_url}")
                # Простой парсинг robots.txt
                for line in response.text.split('\n'):
                    if line.lower().startswith('disallow:'):
                        path = line.split(':')[1].strip()
                        self.logger.debug(f"Запрещенный путь: {path}")
        except Exception as e:
            self.logger.debug(f"Не удалось получить robots.txt: {str(e)}")
        finally:
            self.robots_txt_checked = True

    def _is_valid_url(self, url: str) -> bool:
        """Проверка валидности URL и принадлежности к целевому домену"""
        if not url.startswith(('http://', 'https://')):
            return False
            
        ext = tldextract.extract(url)
        return (ext.domain == self.base_ext.domain and 
                ext.suffix == self.base_ext.suffix)

    def _normalize_url(self, url: str) -> str:
        """Нормализация URL путем удаления фрагментов и параметров запроса"""
        return url.split('#')[0].split('?')[0].rstrip('/')

    def _extract_links(self, html: str, base_url: str) -> Set[str]:
        """Извлечение всех уникальных ссылок из HTML"""
        soup = BeautifulSoup(html, 'html.parser')
        links = set()
        
        # Поиск ссылок в HTML-тегах
        for tag in soup.find_all(['a', 'link', 'img', 'script', 'iframe']):
            url = tag.get('href') or tag.get('src') or tag.get('data-src')
            if url:
                absolute_url = urljoin(base_url, url)
                normalized_url = self._normalize_url(absolute_url)
                if self._is_valid_url(normalized_url):
                    links.add(normalized_url)
        
        # Поиск API-эндпоинтов в JavaScript-коде
        script_tags = soup.find_all('script')
        for script in script_tags:
            if script.string:
                api_calls = re.findall(
                    r"(?:fetch|axios|ajax|\.get|\.post)\(['\"](.*?)['\"]",
                    script.string
                )
                for api in api_calls:
                    absolute_api = urljoin(base_url, api)
                    normalized_api = self._normalize_url(absolute_api)
                    if self._is_valid_url(normalized_api):
                        links.add(normalized_api)
                        self._stats['api_endpoints'] += 1
        
        return links

    def _extract_forms(self, html: str, base_url: str) -> List[Dict]:
        """Извлечение всех форм из HTML с их полями ввода"""
        soup = BeautifulSoup(html, 'html.parser')
        forms = []
        
        for form in soup.find_all('form'):
            form_data = {
                'action': urljoin(base_url, form.get('action', '')),
                'method': form.get('method', 'get').upper(),  # Приведение к верхнему регистру
                'inputs': []  # Список полей формы
            }
            
            # Извлечение всех полей ввода
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'name': input_tag.get('name'),      # Имя поля
                    'type': input_tag.get('type', 'text'),  # Тип (по умолчанию text)
                    'value': input_tag.get('value', '')  # Значение
                }
                form_data['inputs'].append(input_data)
            
            forms.append(form_data)
        
        return forms

    def crawl(self) -> Dict[str, List]:
        """Основной метод сканирования с комплексной обработкой ошибок"""
        if not self.robots_txt_checked:
            self._check_robots_txt()
            
        self.queue.append(self.base_url)
        results = {
            'urls': [],        # Список найденных URL
            'forms': [],       # Список найденных форм
            'api_endpoints': []  # Список API-эндпоинтов
        }
        
        # Основной цикл сканирования
        while self.queue and len(self.visited_urls) < self.max_pages:
            current_url = self.queue.pop(0)
            
            if current_url in self.visited_urls:
                continue
                
            try:
                self.logger.info(f"Сканирование: {current_url}")
                time.sleep(self.delay)  # Задержка между запросами
                
                # Выполнение HTTP-запроса
                response = self.session.get(
                    current_url,
                    timeout=15,
                    allow_redirects=True,
                    stream=False
                )
                
                # Пропуск неудачных запросов
                if response.status_code != 200:
                    self.logger.debug(f"Пропуск {current_url} (статус: {response.status_code})")
                    continue
                    
                # Проверка типа содержимого
                content_type = response.headers.get('content-type', '')
                if 'text/html' not in content_type:
                    self.logger.debug(f"Пропуск не-HTML контента: {content_type}")
                    continue
                    
                # Обработка успешного ответа
                self.visited_urls.add(current_url)
                results['urls'].append(current_url)
                self._stats['pages_crawled'] += 1
                
                html = response.text
                
                # Извлечение и обработка ссылок
                new_links = self._extract_links(html, current_url)
                for link in new_links:
                    if link not in self.visited_urls and link not in self.queue:
                        self.queue.append(link)
                        self._stats['links_found'] += 1
                
                # Извлечение форм
                forms = self._extract_forms(html, current_url)
                results['forms'].extend(forms)
                self._stats['forms_found'] += len(forms)
                
            except requests.exceptions.RequestException as e:
                self.logger.warning(f"Ошибка запроса для {current_url}: {str(e)}")
                if self.debug:
                    self.logger.debug("Полное исключение:", exc_info=True)
            except Exception as e:
                self.logger.error(f"Ошибка обработки {current_url}: {str(e)}", exc_info=True)
                if self.debug:
                    raise  # Повторное возбуждение исключения в режиме отладки
                
        self.logger.info(f"Сканирование завершено. Статистика: {self._stats}")
        return results

    @property
    def stats(self) -> Dict[str, int]:
        """Получение статистики сканирования"""
        return self._stats.copy()