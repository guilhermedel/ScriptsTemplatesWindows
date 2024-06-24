import os
import sys
import argparse

def is_dotnet_installed():
    try:
        return_code = os.system('dotnet --version')
        if return_code != 0:
            print(".NET SDK não está instalado ou não está no PATH.")
            return False
        print(".NET SDK está instalado e configurado no PATH.")
        return True
    except Exception as e:
        print(f"Ocorreu um erro ao verificar a instalação do .NET SDK: {e}")
        sys.exit(1)

def download_dotnet_installer(version='8.0'):
    installer_path = os.system(f'winget install Microsoft.DotNet.SDK.{version}')
    try:
        print(f"Baixando o instalador do .NET SDK versão {version} ...")
        # urllib.request.urlretrieve(url, installer_path)
        print(f"Instalador baixado para {installer_path}.")
        return installer_path
    except Exception as e:
        print(f"Ocorreu um erro ao baixar o instalador do .NET SDK: {e}")
        sys.exit(1)

def install_dotnet(installer_path):
    try:
        print("Executando o instalador do .NET SDK...")
        os.system(f'powershell -Command "Start-Process \'{installer_path}\' -ArgumentList \'/install /quiet /norestart\' -Verb runAs"')
        print("A instalação do .NET SDK foi iniciada. Pode demorar alguns minutos.")
    except Exception as e:
        print(f"Ocorreu um erro ao executar o instalador do .NET SDK: {e}")
        sys.exit(1)
        
def create_dotnet_project(project_name):
    try:
        print(f"Criando o projeto .NET '{project_name}'...")
        return_code = os.system(f'dotnet new webapi -n {project_name}')
        if return_code != 0:
            print("Houve um erro na criação do projeto .NET.")
            sys.exit(1)
        print(f"O projeto .NET '{project_name}' foi criado com sucesso.")
    except Exception as e:
        print(f"Ocorreu um erro inesperado ao criar o projeto .NET: {e}")
        sys.exit(1)

def create_directories(project_name, directories):
    try:
        base_path = os.path.join(project_name)
        for directory in directories:
            os.makedirs(os.path.join(base_path, directory), exist_ok=True)
        print(f"As pastas {', '.join(directories)} foram criadas dentro de '{project_name}'.")
    except Exception as e:
        print(f"Ocorreu um erro ao criar as pastas: {e}")
        sys.exit(1)
        
def install_ef_core_package(project_name, database):
    package_mapping = {
        'sqlserver': 'Microsoft.EntityFrameworkCore.SqlServer',
        'mysql': 'Pomelo.EntityFrameworkCore.MySql',
        'postgresql': 'Npgsql.EntityFrameworkCore.PostgreSQL',
        'sqlite': 'Microsoft.EntityFrameworkCore.Sqlite'
    }
    
    if database not in package_mapping:
        print(f"Banco de dados '{database}' não suportado.")
        sys.exit(1)
    
    package_name = package_mapping[database]
    try:
        print(f"Instalando o pacote '{package_name}' para o Entity Framework Core...")
        os.chdir(project_name)
        return_code = os.system(f'dotnet add package {package_name}')
        if return_code != 0:
            print(f"Houve um erro na instalação do pacote '{package_name}'.")
            sys.exit(1)
        print(f"O pacote '{package_name}' foi instalado com sucesso.")
    except Exception as e:
        print(f"Ocorreu um erro ao instalar o pacote '{package_name}': {e}")
        sys.exit(1)
    finally:
        os.chdir('..')
        
def is_docker_installed():
    try:
        return_code = os.system('docker --version')
        if return_code != 0:
            print("Docker não está instalado ou não está no PATH.")
            sys.exit(1)
        print("Docker está instalado e configurado no PATH.")
    except Exception as e:
        print(f"Ocorreu um erro ao verificar a instalação do Docker: {e}")
        sys.exit(1)
        
def create_docker_compose_file(project_name, database, db_user, db_password, db_name):
    content_mapping = {
        'sqlserver': f'''
version: '3.8'
services:
  sqlserver:
    image: mcr.microsoft.com/mssql/server:2019-latest
    container_name: sqlserver_container
    environment:
      SA_PASSWORD: "{db_password}"
      ACCEPT_EULA: "Y"
    ports:
      - "1433:1433"
    volumes:
      - sqlserver_data:/var/opt/mssql

volumes:
  sqlserver_data:
        ''',
        'mysql': f'''
version: '3.8'
services:
  mysql:
    image: mysql:latest
    container_name: mysql_container
    environment:
      MYSQL_ROOT_PASSWORD: {db_password}
      MYSQL_USER: {db_user}
      MYSQL_PASSWORD: {db_password}
      MYSQL_DATABASE: {db_name}
    ports:
      - "3306:3306"
    volumes:
      - mysql_data:/var/lib/mysql

volumes:
  mysql_data:
        ''',
        'postgresql': f'''
version: '3.8'
services:
  postgres:
    image: postgres:latest
    container_name: postgres_container
    environment:
      POSTGRES_USER: {db_user}
      POSTGRES_PASSWORD: {db_password}
      POSTGRES_DB: {db_name}
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
        ''',
        'sqlite': f'''
version: '3.8'
services:
  sqlite:
    image: nouchka/sqlite3
    container_name: sqlite_container
    environment:
      SQLITE_USER: {db_user}
      SQLITE_PASSWORD: {db_password}
    ports:
      - "8080:8080"
    volumes:
      - sqlite_data:/data

volumes:
  sqlite_data:
        '''
    }

    if database not in content_mapping:
        print(f"Banco de dados '{database}' não suportado para Docker Compose.")
        sys.exit(1)

    try:
        compose_file_path = os.path.join(project_name, 'docker-compose.yml')
        with open(compose_file_path, 'w') as file:
            file.write(content_mapping[database])
        print(f"Arquivo 'docker-compose.yml' criado com sucesso dentro do projeto '{project_name}'.")
    except Exception as e:
        print(f"Ocorreu um erro ao criar o arquivo 'docker-compose.yml': {e}")
        sys.exit(1)

def start_docker_compose(project_name):
    try:
        os.chdir(project_name)
        return_code = os.system('docker-compose up -d')
        if return_code != 0:
            print("Houve um erro ao iniciar o Docker Compose.")
            sys.exit(1)
        print("Docker Compose iniciado com sucesso.")
    except Exception as e:
        print(f"Ocorreu um erro ao iniciar o Docker Compose: {e}")
        sys.exit(1)
    finally:
        os.chdir('..')
        
def create_auth_service(project_name):
    services_path = os.path.join(project_name, 'Services')
    os.makedirs(services_path, exist_ok=True)

    auth_service_content = f'''
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using {project_name}.Dtos;
using {project_name}.Models;
using {project_name}.Utils.Encryption;
using {project_name}.Data;
using Microsoft.EntityFrameworkCore;

namespace {project_name}.Services
{{
    public class AuthService : IAuthService
    {{
        private readonly List<User> _users = new List<User>();
        private readonly string _key;

        private readonly ApplicationDbContext _context;

        public AuthService(ApplicationDbContext context,IConfiguration configuration)
        {{
            _context = context;
            _key = configuration["Jwt:Key"];
        }}

       public async Task<bool> Authenticate(string email,string password)
        {{
            User user = await _context.Users.FirstOrDefaultAsync(u => u.Email.Equals(email));
            if (user == null) return false;

            return EncryptionService.VerifyPassword(password, user.Password);
        }}

        public async Task<User> Register(UserRegisterDto userRegisterDto)
        {{
            if (await _context.Users.AnyAsync(u => u.Email == userRegisterDto.Email))
                return null;

            var newUser = new User
            {{
                Cpf = userRegisterDto.Cpf,
                Name = userRegisterDto.Name,
                Email = userRegisterDto.Email,
                Password = EncryptionService.EncryptPassword(userRegisterDto.Password),
                Phone = userRegisterDto.Phone,
                BirthdayDate = DateTime.SpecifyKind(userRegisterDto.BirthdayDate, DateTimeKind.Utc)
            }};

            _context.Users.AddAsync(newUser);
            await _context.SaveChangesAsync();

            return newUser;
        }}
    }}
}}
    '''

    auth_service_path = os.path.join(services_path, 'AuthService.cs')
    with open(auth_service_path, 'w') as file:
        file.write(auth_service_content)
    print(f"Arquivo 'AuthService.cs' criado com sucesso em {auth_service_path}")

def create_i_auth_service(project_name):
    services_path = os.path.join(project_name, 'Services')
    os.makedirs(services_path, exist_ok=True)

    i_auth_service_content = f'''
using {project_name}.Dtos;
using {project_name}.Models;

namespace {project_name}.Services
{{
    public interface IAuthService
    {{
        Task<bool> Authenticate(string email,string password);
        Task<User> Register(UserRegisterDto userRegisterDto);
    }}
}}
    '''

    i_auth_service_path = os.path.join(services_path, 'IAuthService.cs')
    with open(i_auth_service_path, 'w') as file:
        file.write(i_auth_service_content)
    print(f"Arquivo 'IAuthService.cs' criado com sucesso em {i_auth_service_path}")




if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Cria um projeto .NET.')
    parser.add_argument('--projectName', type=str, required=True, help='Nome do projeto .NET a ser criado')
    parser.add_argument('--directories', nargs='+', default=['Models', 'Controllers', 'Services','Dtos','Data','Utils'], help='Nomes das pastas a serem criadas dentro do projeto')
    parser.add_argument('--database', type=str, required=True, choices=['sqlserver', 'mysql', 'postgresql', 'sqlite'], help='Banco de dados a ser utilizado com Entity Framework Core')
    parser.add_argument('--dbUser', type=str, required=True, help='Usuário do banco de dados')
    parser.add_argument('--dbPassword', type=str, required=True, help='Senha do banco de dados')
    parser.add_argument('--dbName', type=str, required=True, help='Senha do banco de dados')
    
    args = parser.parse_args()
    if not is_dotnet_installed():
        installer_path = download_dotnet_installer('8.0')
        install_dotnet(installer_path)
    else:
        print(".NET SDK já está instalado.")
    create_dotnet_project(args.projectName)
    create_directories(args.projectName, args.directories)
    
    # Criação dos arquivos
    create_auth_service(args.projectName)
    create_i_auth_service(args.projectName)
    
    # ------------------------------------------------------
    install_ef_core_package(args.projectName, args.database)
    is_docker_installed()
    create_docker_compose_file(args.projectName, args.database, args.dbUser, args.dbPassword,args.dbName)
    start_docker_compose(args.projectName)
    
    
    