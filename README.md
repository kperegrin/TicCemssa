Requisits:
# Requisits Python
pkg install -y python3 py311-pip

# Libreries Python
/usr/local/bin/python3 -m pip install pypdf
/usr/local/bin/python3 -m pip install torch
/usr/local/bin/python3 -m pip install transformers
/usr/local/bin/python3 -m pip install huggingface_hub
/usr/local/bin/python3 -m pip install safetensors
/usr/local/bin/python3 -m pip install tokenizers

# Tot Junt
/usr/local/bin/python3 -m pip install pypdf torch transformers huggingface_hub safetensors tokenizers

# Instalar Model Local

/usr/local/bin/python3 /usr/local/etc/inspector.py --install-ner-model

