#!/bin/bash

# Criar virtual environment
python3 -m venv venv

# Ativar venv
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Instalar dependências
pip install -r requirements.txt

echo "Virtual environment ready!"
