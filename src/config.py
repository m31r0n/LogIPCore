# src/config.py
import os
import configparser

def load_config(config_file='../config/config.ini'):
    config = configparser.ConfigParser()
    config.read(config_file)
    
    # Asignar API keys a variables de entorno
    if 'APIS' in config:
        os.environ['IP_ABUSE_API_KEY'] = config['APIS'].get('ipabuse_key', '')
        os.environ['VIRUSTOTAL_API_KEY'] = config['APIS'].get('virustotal_key', '')
        os.environ['CRIMINAL_IP_API_KEY'] = config['APIS'].get('criminalip_key', '')
    
    # Puedes devolver otras configuraciones si las necesitas
    return config
