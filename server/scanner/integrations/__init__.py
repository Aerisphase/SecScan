"""
Модуль интеграций сканера с внешними системами
"""

from .telegram import TelegramNotifier
from .slack import SlackNotifier
from .ci_cd import GitHubActionsIntegration, GitLabCIIntegration
from .ide import VSCodePlugin, JetBrainsPlugin
from .waf import CloudflareIntegration, ModSecurityIntegration

# Версия модуля интеграций
__version__ = "1.0.0"

# Доступные интеграции по категориям
NOTIFIERS = {
    'telegram': TelegramNotifier,
    'slack': SlackNotifier
}

CI_SYSTEMS = {
    'github': GitHubActionsIntegration,
    'gitlab': GitLabCIIntegration
}

IDE_PLUGINS = {
    'vscode': VSCodePlugin,
    'jetbrains': JetBrainsPlugin
}

WAF_INTEGRATIONS = {
    'cloudflare': CloudflareIntegration,
    'modsecurity': ModSecurityIntegration
}

__all__ = [
    'TelegramNotifier',
    'SlackNotifier',
    'GitHubActionsIntegration',
    'GitLabCIIntegration',
    'VSCodePlugin',
    'JetBrainsPlugin',
    'CloudflareIntegration',
    'ModSecurityIntegration',
    'NOTIFIERS',
    'CI_SYSTEMS',
    'IDE_PLUGINS',
    'WAF_INTEGRATIONS',
    '__version__'
]

class IntegrationError(Exception):
    """Базовое исключение для ошибок интеграций"""
    pass

def get_integration(integration_type: str, name: str):
    """
    Фабричный метод для получения интеграции по типу и имени
    
    :param integration_type: Один из ['notifier', 'ci', 'ide', 'waf']
    :param name: Имя интеграции (например 'telegram')
    :return: Класс интеграции
    :raises IntegrationError: Если интеграция не найдена
    """
    mappings = {
        'notifier': NOTIFIERS,
        'ci': CI_SYSTEMS,
        'ide': IDE_PLUGINS,
        'waf': WAF_INTEGRATIONS
    }
    
    if integration_type not in mappings:
        raise IntegrationError(f"Unknown integration type: {integration_type}")
    
    available = mappings[integration_type]
    if name not in available:
        raise IntegrationError(
            f"Integration '{name}' not found. Available: {list(available.keys())}"
        )
    
    return available[name]