# Esquema da Base de Dados - Relações

| Tabela                  | Relações principais                                                                             | Por quê?                                                                 |
| ----------------------- | ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| **User**                | `public_key (1:1)`, `vault (1:1)`, `clearances (1:N)`, `transfers (1:N)`, `audit_entries (1:N)` | Centraliza identidade, chaves, permissões e histórico.                   |
| **UserPublicKey**       | `user (N:1)`                                                                                    | Chave pública necessária para criptografia de file key por destinatário. |
| **UserVault**           | `user (N:1)`                                                                                    | Blob criptografado com a chave privada do usuário (nunca em claro).      |
| **ClearanceToken**      | `user (N:1)`, `issuer (N:1)`, `revocations (1:N)`                                               | Token assinado pelo Security Officer; expira e pode ser revogado.        |
| **ClearanceRevocation** | `token (N:1)`, `revoker (N:1)`                                                                  | Revogação explícita (CRL-like).                                          |
| **Transfer**            | `uploader (N:1)`, `encrypted_keys (1:N)`                                                        | Metadados da transferência + chaves por destinatário.                    |
| **EncryptedFileKey**    | `transfer (N:1)`, `recipient (N:1)`                                                             | E2E: cada destinatário recebe a file key cifrada com sua pubkey.         |
| **AuditLog**            | `actor (N:1)`, `verifications (1:N)`                                                            | Hash-chain garante integridade; cada linha referencia a anterior.        |
| **AuditVerification**   | `log_entry (N:1)`, `auditor (N:1)`                                                              | Auditor assina ponto da cadeia → Verification Object.                    |
| **Department**          | não tem FK direta – usado via JSON em ClearanceToken e Transfer                                 | Modelo lattice do MLS: níveis + compartimentos (departamentos).          |

# Modelo de Dados - SecureShare

## 1. `users` – Gerenciamento de Identidade e Papéis (RBAC)

| Campo                         | Função                                                                |
| ----------------------------- | --------------------------------------------------------------------- |
| `id`                          | Identificador único do usuário                                        |
| `username`                    | Login único (ex: alice@org)                                           |
| `password_hash`               | Senha criptografada (Argon2/PBKDF2)                                   |
| `one_time_password`           | Senha temporária para ativação (nula após uso)                        |
| `is_active`                   | Indica se o usuário já foi ativado                                    |
| `role`                        | RBAC: USER, SECURITY_OFFICER, TRUSTED_OFFICER, AUDITOR, ADMINISTRATOR |
| `created_at` / `activated_at` | Auditoria de ciclo de vida                                            |

**Função principal:** Centraliza autenticação, autorização (RBAC) e estado do usuário. O único ADMINISTRATOR é criado na inicialização. Usuários começam desativados até ativarem com OTP.

---

## 2. `departments` – Categorias do MLS (Compartimentos)

| Campo        | Função                                         |
| ------------ | ---------------------------------------------- |
| `id`         | PK                                             |
| `name`       | Nome do departamento: Finance, HR, Engineering |
| `created_at` | Auditoria                                      |

**Função principal:** Define compartimentos não hierárquicos do modelo Bell-LaPadula com categorias. Usado como label em clearances e arquivos. Apenas o Administrator pode criar/remover.

---

## 3. `user_public_keys` – Distribuição de Chaves Públicas

| Campo               | Função                                       |
| ------------------- | -------------------------------------------- |
| `user_id` (PK + FK) | Relaciona à users                            |
| `public_key`        | Chave pública (PEM/base64) para criptografia |
| `uploaded_at`       | Quando foi enviada                           |

**Função principal:** Permite que qualquer usuário criptografe a File Key para outro. Necessária para compartilhamento privado (user-specific). Nunca armazena a chave privada.

---

## 4. `user_vaults` – Armazenamento Seguro da Chave Privada

| Campo               | Função                                                           |
| ------------------- | ---------------------------------------------------------------- |
| `user_id` (PK + FK) | Relaciona ao dono                                                |
| `encrypted_blob`    | Chave privada criptografada com senha do usuário (PBKDF2/Argon2) |
| `updated_at`        | Quando foi atualizado                                            |

**Função principal:** Armazena a chave privada do usuário no servidor, mas criptografada. Cliente baixa o blob → descriptografa com senha → usa em memória. Garante E2E: servidor nunca vê a chave privada.

---

## 5. `clearance_tokens` – Credenciais de Segurança (MLS)

| Campo                      | Função                                                         |
| -------------------------- | -------------------------------------------------------------- |
| `id`                       | PK                                                             |
| `user_id`                  | Quem recebe o clearance                                        |
| `level`                    | Nível: UNCLASSIFIED → TOP_SECRET                               |
| `departments_json`         | ["Finance", "HR"] – quais departamentos o usuário pode acessar |
| `issued_by`                | Security Officer que assinou                                   |
| `issued_at` / `expires_at` | Validade temporal                                              |
| `signature`                | Assinatura criptográfica do token                              |

**Função principal:** Representa a clearance do usuário no modelo MLS (lattice). Token curto-vivo, assinado, apresentado em cada requisição sensível. Usado para validar No Read Up e No Write Down.

---

## 6. `clearance_revocations` – Revogação de Clearances

| Campo        | Função                          |
| ------------ | ------------------------------- |
| `token_id`   | Qual clearance foi revogada     |
| `revoked_by` | Quem revogou (Security Officer) |
| `revoked_at` | Quando                          |
| `signature`  | Assinatura da revogação         |

**Função principal:** Implementa CRL (Certificate Revocation List) para clearances. Antes de aceitar um token, o servidor verifica se há revogação.

---

## 7. `transfers` – Transferência de Arquivos (Objeto de Dados)

| Campo                  | Função                                             |
| ---------------------- | -------------------------------------------------- |
| `id`                   | PK                                                 |
| `uploader_id`          | Quem fez upload                                    |
| `classification_level` | Nível do arquivo (ex: SECRET)                      |
| `departments_json`     | Departamentos do arquivo ([] = organização geral)  |
| `is_public`            | True → link com chave no fragment; False → privado |
| `expires_at`           | Expiração obrigatória (ex: 7 dias)                 |
| `created_at`           | Quando foi criado                                  |
| `deleted_at`           | Soft-delete (para auditoria)                       |
| `metadata_json`        | Nome, tamanho, MIME, etc.                          |

**Função principal:** Armazena metadados do arquivo criptografado. Define classificação MLS do objeto. Controla expiração automática.

---

## 8. `encrypted_file_keys` – Chaves de Arquivo por Destinatário (E2E)

| Campo           | Função                                           |
| --------------- | ------------------------------------------------ |
| `transfer_id`   | Qual transferência                               |
| `recipient_id`  | Quem pode descriptografar                        |
| `encrypted_key` | File Key criptografada com a pubkey do recipient |

**Função principal:** Permite compartilhamento privado seguro. Cada destinatário recebe sua própria cópia da chave simétrica. Servidor não tem acesso à chave em claro.

---

## 9. `audit_log` – Registro Imutável de Ações (Hash Chain)

| Campo          | Função                                                |
| -------------- | ----------------------------------------------------- |
| `id`           | PK                                                    |
| `event_type`   | USER_CREATED, FILE_UPLOADED, CLEARANCE_ISSUED, etc.   |
| `actor_id`     | Quem realizou a ação                                  |
| `target_id`    | Objeto afetado (usuário, transferência, etc.)         |
| `details_json` | Dados estruturados                                    |
| `timestamp`    | Quando ocorreu                                        |
| `prev_hash`    | Hash da entrada anterior                              |
| `current_hash` | Hash desta entrada (SHA256(prev + dados + timestamp)) |

**Função principal:** Garante integridade e não-repúdio de todas as ações. Hash chain: cada entrada depende da anterior → impossível alterar sem quebrar a cadeia. Apenas Auditors podem ler.

---

## 10. `audit_verifications` – Validação do Log pelo Auditor

| Campo        | Função                                             |
| ------------ | -------------------------------------------------- |
| `log_id`     | Qual entrada do log está sendo validada            |
| `auditor_id` | Quem validou                                       |
| `statement`  | Texto: "Log válido até entrada #123"               |
| `timestamp`  | Quando                                             |
| `signature`  | Assinatura do auditor sobre o prev_hash da entrada |

**Função principal:** Auditor assina um ponto da hash chain como válido. Garante terceirização de confiança e auditabilidade externa.
