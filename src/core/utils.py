from urllib.parse import urlparse
import tldextract

def normalize_url(url: str) -> str:
    """Нормализация URL"""
    return url.split('#')[0].split('?')[0].rstrip('/')

def is_same_domain(url1: str, url2: str) -> bool:
    """Проверка принадлежности к одному домену"""
    ext1 = tldextract.extract(url1)
    ext2 = tldextract.extract(url2)
    return ext1.domain == ext2.domain and ext1.suffix == ext2.suffix