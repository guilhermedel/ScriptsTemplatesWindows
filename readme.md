# Dotnet Templates ShellScripts
Esse repositorio contem alguns templates de aplicações dotnet para rodar pelo powershell

### Criar Variável de Ambiente

1. Abra o `PowerShell` como administrador.
2. Defina a variável de ambiente adicionando o caminho do diretório onde o script está localizado:

```powershell
$env:Path += ";C:\caminho\para\seu\script"
```

### Habilitar Execução de Scripts

1. No `PowerShell` como administrador, permita a execução de scripts:

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## Utilização

### Executando o Script

1. Navegue até o diretório onde o script está localizado ou certifique-se de que o diretório está incluído no `Path`.
2. Execute o script com o comando:

```powershell
.\dotnet.ps1 -projectName "MyApiProject" -template "auth"
```

### Argumentos do Script

- `-projectName`: Nome do projeto a ser criado.
- `-folders`: (Opcional) Array de nomes de pastas adicionais a serem criadas. Padrão: `@("Models", "Services", "Utils")`
- `-template`: (Opcional) Define um template específico a ser usado. Atualmente, suporta "auth" para incluir pastas e arquivos relacionados à autenticação.

### Exemplo de Uso

```powershell
.\dotnet.ps1 -projectName "MyApiProject" -folders @("Models", "Services", "Utils", "Repositories") -template "auth"
```

Este comando criará um novo projeto chamado `MyApiProject` com as pastas `Models`, `Services`, `Utils` e `Repositories`, além de adicionar arquivos relacionados à autenticação.


## Considerações Finais

Este script e documentação são apenas um ponto de partida para o desenvolvimento da sua API. Certifique-se de ajustar as configurações e o código conforme as necessidades do seu projeto.
```