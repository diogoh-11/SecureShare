# Guia Rápido: Testando Detecção de Adulteração

## Preparação

1. **Certifique-se que o servidor está rodando e tem dados**:
```bash
setup_test_env.sh
```

2. **Verificar que chain está válida**:
```bash
sshare login --username auditor --password auditor_pass
sshare audit verify
```

Deve mostrar: `"valid": true`

---

## Método 1: Usando SQL Direto (Mais Simples)

### Opção A: Alterar campo `action` (mudar conteúdo)

```bash
# Entrar no container
docker exec -it secureshare-server bash

# Abrir database
sqlite3 /app/secureshare.db

# Ver entries
SELECT id, action, entryHash FROM audit_log;

# Escolher uma entry (ex: #2) e adulterar
UPDATE audit_log 
SET action = 'TAMPERED: This action was changed!' 
WHERE id = 2;

# Sair
.quit
exit
```

**Testar detecção**:
```bash
sshare audit verify
```

**Resultado esperado**:
```json
{
  "valid": false,
  "message": "Entry 2 content has been tampered with",
  "entry_id": 2,
  "expected_hash": "novo_hash_calculado...",
  "stored_hash": "hash_antigo_guardado...",
  "tampering_type": "content_modification"
}
```

---

### Opção B: Alterar `entryHash` (quebrar link da chain)

```bash
docker exec -it secureshare-server bash
sqlite3 /app/secureshare.db

# Alterar hash da entry #2
UPDATE audit_log 
SET entryHash = '0000000000000000000000000000000000000000000000000000000000000000' 
WHERE id = 2;

.quit
exit
```

**Testar**:
```bash
sshare audit verify
```

**Resultado esperado**:
```json
{
  "valid": false,
  "message": "Hash chain broken at entry 3",
  "entry_id": 3,
  "expected": "0000000000000000...",
  "actual": "hash_que_entry_3_esperava..."
}
```

---

### Opção C: Apagar uma entry

```bash
docker exec -it secureshare-server bash
sqlite3 /app/secureshare.db

# Apagar entry do meio
DELETE FROM audit_log WHERE id = 2;

# Ver o gap
SELECT id FROM audit_log ORDER BY id;

.quit
exit
```

**Testar**:
```bash
sshare audit verify
```

**Resultado esperado**:
```json
{
  "valid": false,
  "message": "Hash chain broken at entry 3",
  "entry_id": 3,
  "expected": "hash_da_entry_1...",
  "actual": "hash_da_entry_2_que_nao_existe..."
}
```

---