import sys

with open("apps.yaml", "r") as f:
    content = f.read()

content = content.replace(
    '''  - id: nabugate
    name: NabuGate AI
    description: Unified LLM, vision and multi-model gateway
    icon: cpu-chip
    url: https://gate.nabuxai.com
    badge: Active
    redirect_uris:
      - https://gate.nabuxai.com/admin/api/nabu/callback''',
    '''  - id: nabugate
    name: NabuGate AI
    description: Unified LLM, vision and multi-model gateway
    icon: cpu-chip
    url: https://gate.nabuxai.com
    badge: Active
    redirect_uris:
      - https://gate.nabuxai.com/admin/api/nabu/callback
      - https://gate.nabuxai.com/api/nabu/callback
      - http://localhost:8080/api/nabu/callback
      - http://localhost:8080/admin/api/nabu/callback'''
)

with open("apps.yaml", "w") as f:
    f.write(content)
