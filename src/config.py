# src/config.py
import os
import configparser
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent


def load_config():
    """Carga API keys desde .env, con fallback a config.ini."""
    try:
        from dotenv import load_dotenv
        env_path = PROJECT_ROOT / '.env'
        if env_path.exists():
            load_dotenv(env_path)
    except ImportError:
        pass

    config = configparser.ConfigParser()
    config.read(PROJECT_ROOT / 'config' / 'config.ini')

    if 'APIS' in config:
        for env_key, ini_key in [
            ('IP_ABUSE_API_KEY', 'ipabuse_key'),
            ('VIRUSTOTAL_API_KEY', 'virustotal_key'),
            ('CRIMINAL_IP_API_KEY', 'criminalip_key'),
        ]:
            if not os.environ.get(env_key):
                os.environ[env_key] = config['APIS'].get(ini_key, '')

    return config


def get_output_folder():
    """Retorna carpeta output/ en la raíz del proyecto."""
    output = PROJECT_ROOT / 'output'
    output.mkdir(parents=True, exist_ok=True)
    return str(output)


def get_data_folder():
    """Retorna carpeta data/ en la raíz del proyecto."""
    return str(PROJECT_ROOT / 'data')
