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
        
def add_project_dependencies(project_name, database):
    os.chdir(project_name)

    dependencies = [
        'Microsoft.EntityFrameworkCore',
        'Microsoft.EntityFrameworkCore.Design',
        'Microsoft.EntityFrameworkCore.Tools',
        'Microsoft.AspNetCore.Authentication.JwtBearer',
        'Swashbuckle.AspNetCore'
    ]

    db_dependencies = {
        'sqlserver': 'Microsoft.EntityFrameworkCore.SqlServer',
        'mysql': 'Pomelo.EntityFrameworkCore.MySql',
        'postgresql': 'Npgsql.EntityFrameworkCore.PostgreSQL',
        'sqlite': 'Microsoft.EntityFrameworkCore.Sqlite'
    }

    if database in db_dependencies:
        dependencies.append(db_dependencies[database])
    else:
        print(f"Banco de dados '{database}' não suportado.")
        sys.exit(1)

    for dependency in dependencies:
        try:
            os.system(f'dotnet add package {dependency}')
            print(f"Dependência '{dependency}' adicionada com sucesso.")
        except Exception as e:
            print(f"Houve um erro ao adicionar a dependência '{dependency}': {e}")
            sys.exit(1)
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
        os.system('start "C:\Program Files\Docker\Docker\Docker Desktop.exe"')
        os.chdir(project_name)
        return_code = os.system('docker-compose up -d')
        if return_code != 0:
            print("Houve um erro ao iniciar o Docker Compose.")
            sys.exit(1)
        os.system('dotnet ef migrations add "initialMigration"')
        os.system('dotnet ef database update')
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

            User newUser = new User
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

def create_auth_controller(project_name):
    controllers_path = os.path.join(project_name, 'Controllers')
    os.makedirs(controllers_path, exist_ok=True)

    auth_controller_content = f'''
using Microsoft.AspNetCore.Mvc;
using {project_name}.Dtos;
using {project_name}.Services;
using {project_name}.Utils.Encryption;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

namespace {project_name}.Controllers
{{
    [Route("api/auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {{
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {{
            _authService = authService;
        }}

        [HttpGet("login")]
        public async Task<IActionResult> Login()
        {{
            var authHeader = AuthenticationHeaderValue.Parse(Request.Headers["Authorization"]);
            if (authHeader.Scheme is not "Basic")
                return Unauthorized("ASDasD");

            var credentials = Encoding.ASCII.GetString(
                Convert.FromBase64String(authHeader.Parameter)
            );
            var separatorIndex = credentials.IndexOf(':');
            string email = credentials.Substring(0, separatorIndex);
            string password = credentials.Substring(separatorIndex + 1);
            bool isLoginValid = await _authService.Authenticate(email, password);

            if (!isLoginValid)
                return NotFound("Login inválido.");
                
            string token = EncryptionService.GenerateToken(email);

            return Ok(new {{ Token = token }});
        }}
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] UserRegisterDto userRegisterDto)
        {{
            var user = await _authService.Register(userRegisterDto);
            if (user == null)
                return BadRequest("Email já registrado!");
            
            return Ok(user);
        }}
    }}
}}
    '''

    auth_controller_path = os.path.join(controllers_path, 'AuthController.cs')
    with open(auth_controller_path, 'w') as file:
        file.write(auth_controller_content)
    print(f"Arquivo 'AuthController.cs' criado com sucesso em {auth_controller_path}")
    
def create_user_model(project_name):
    models_path = os.path.join(project_name, 'Models')
    os.makedirs(models_path, exist_ok=True)

    user_model_content = f'''
using System;
using System.ComponentModel.DataAnnotations;

namespace {project_name}.Models
{{
    public class User
    {{
        [Key]
        public Guid Id {{ get; set; }}
        public string Cpf {{ get; set; }}
        public string Name {{ get; set; }}
        public string Email {{ get; set; }}
        public string Password {{ get; set; }}
        public string Phone {{ get; set; }}
        public DateTime BirthdayDate {{ get; set; }}
        
        public User()
        {{
            
        }}

        public User(string name, string email, string phone, string cpf,string password,DateTime birthdayDate)
        {{
            Id = new Guid();
            Cpf = cpf;
            Name = name;
            Email = email;
            Password=password;
            Phone = phone;
            BirthdayDate = birthdayDate; 
        }}
    }}
}}
    '''

    user_model_path = os.path.join(models_path, 'User.cs')
    with open(user_model_path, 'w') as file:
        file.write(user_model_content)
    print(f"Arquivo 'User.cs' criado com sucesso em {user_model_path}")

def create_user_login_dto(project_name):
    dtos_path = os.path.join(project_name, 'Dtos')
    os.makedirs(dtos_path, exist_ok=True)

    user_login_dto_content = f'''
namespace {project_name}.Dtos
{{
    public class UserLoginDto
    {{
        public string Email {{ get; set; }}
        public string Password {{ get; set; }}
    }}
}}
    '''

    user_login_dto_path = os.path.join(dtos_path, 'UserLoginDto.cs')
    with open(user_login_dto_path, 'w') as file:
        file.write(user_login_dto_content)
    print(f"Arquivo 'UserLoginDto.cs' criado com sucesso em {user_login_dto_path}")

def create_user_register_dto(project_name):
    dtos_path = os.path.join(project_name, 'Dtos')
    os.makedirs(dtos_path, exist_ok=True)

    user_register_dto_content = f'''
using System;

namespace {project_name}.Dtos
{{
    public class UserRegisterDto
    {{
        public string Cpf {{ get; set; }}
        public string Name {{ get; set; }}
        public string Email {{ get; set; }}
        public string Password {{ get; set; }}
        public string Phone {{ get; set; }}
        public DateTime BirthdayDate {{ get; set; }}
    }}
}}
    '''

    user_register_dto_path = os.path.join(dtos_path, 'UserRegisterDto.cs')
    with open(user_register_dto_path, 'w') as file:
        file.write(user_register_dto_content)
    print(f"Arquivo 'UserRegisterDto.cs' criado com sucesso em {user_register_dto_path}")

def create_application_db_context(project_name):
    data_path = os.path.join(project_name, 'Data')
    os.makedirs(data_path, exist_ok=True)

    application_db_context_content = f'''
using Microsoft.EntityFrameworkCore;
using {project_name}.Models;

namespace {project_name}.Data
{{
    public class ApplicationDbContext : DbContext
    {{
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {{
        }}

        public DbSet<User> Users {{ get; set; }}

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {{
            base.OnModelCreating(modelBuilder);

            // Configurações adicionais de modelos
        }}
    }}
}}
    '''

    application_db_context_path = os.path.join(data_path, 'ApplicationDbContext.cs')
    with open(application_db_context_path, 'w') as file:
        file.write(application_db_context_content)
    print(f"Arquivo 'ApplicationDbContext.cs' criado com sucesso em {application_db_context_path}")

def create_encryption_service(project_name):
    utils_path = os.path.join(project_name, 'Utils')
    os.makedirs(utils_path, exist_ok=True)

    encryption_service_content = f'''
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace {project_name}.Utils.Encryption
{{
    public static class EncryptionService
    {{
        public static string GenerateToken(string email)
        {{
            var builder = WebApplication.CreateBuilder();
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(builder.Configuration["Jwt:Key"]);
            var tokenDescriptor = new SecurityTokenDescriptor
            {{
                Subject = new ClaimsIdentity(new Claim[] {{ new Claim(ClaimTypes.Name, email) }}),
                Expires = DateTime.UtcNow.AddDays(1),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256
                )
            }};
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }}

        public static string EncryptPassword(string password)
        {{
            using (SHA256 sha256Hash = SHA256.Create())
            {{
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(password));
                // Convert byte array to a string representation
                StringBuilder builder = new();
                for (int i = 0; i < bytes.Length; i++)
                {{
                    builder.Append(bytes[i].ToString("x2"));
                }}
                return builder.ToString();
            }}
        }}

        public static bool VerifyPassword(string password, string hash)
        {{
            string inputHash = EncryptPassword(password);
            return inputHash.Equals(hash, StringComparison.OrdinalIgnoreCase);
        }}
    }}
}}
    '''

    encryption_service_path = os.path.join(utils_path, 'EncryptionService.cs')
    with open(encryption_service_path, 'w') as file:
        file.write(encryption_service_content)
    print(f"Arquivo 'EncryptionService.cs' criado com sucesso em {encryption_service_path}")

def create_appsettings_json(project_name, database, db_user, db_password, db_name):
    connection_strings = {
        'sqlserver': f"Server=localhost;Database={db_name};User Id={db_user};Password={db_password};",
        'mysql': f"Server=localhost;Port=3306;Database={db_name};User={db_user};Password={db_password};",
        'postgresql': f"Host=localhost;Port=5432;Database={db_name};Username={db_user};Password={db_password};",
        'sqlite': f"Data Source={db_name}.db;"
    }

    if database not in connection_strings:
        print(f"Banco de dados '{database}' não suportado.")
        sys.exit(1)

    connection_string = connection_strings[database]

    appsettings_content = f'''
{{
  "ConnectionStrings": {{
    "DefaultConnection": "{connection_string}"
  }},
  "Jwt": {{
    "Key": "s4l0nK3yf0r3ncryptTh3s3P4ss0w0rdN33dM0r3Ch4r4ct3rs"
  }},
  "Logging": {{
    "LogLevel": {{
      "Default": "Information",
      "Microsoft": "Warning",
      "Microsoft.Hosting.Lifetime": "Information"
    }}
  }},
  "AllowedHosts": "*"
}}
    '''

    appsettings_path = os.path.join(project_name, 'appsettings.json')
    with open(appsettings_path, 'w') as file:
        file.write(appsettings_content)
    print(f"Arquivo 'appsettings.json' criado com sucesso em {appsettings_path}")

def create_program_cs(project_name, database):
    db_options = {
        'sqlserver': 'UseSqlServer',
        'mysql': 'UseMySql',
        'postgresql': 'UseNpgsql',
        'sqlite': 'UseSqlite'
    }

    if database not in db_options:
        print(f"Banco de dados '{database}' não suportado.")
        sys.exit(1)

    db_option = db_options[database]

    program_content = f'''
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using {project_name}.Data;
using {project_name}.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.{db_option}(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var key = Encoding.ASCII.GetBytes(builder.Configuration["Jwt:Key"]);

// Configurar JWT
builder.Services.AddAuthentication(options =>
{{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}})
.AddJwtBearer(options =>
{{
    options.TokenValidationParameters = new TokenValidationParameters
    {{
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = false,
        ValidateAudience = false
    }};
}});

builder.Services.AddScoped<IAuthService, AuthService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{{
    app.UseDeveloperExceptionPage();
    app.UseSwagger();
    app.UseSwaggerUI();
}}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
    '''

    program_path = os.path.join(project_name, 'Program.cs')
    with open(program_path, 'w') as file:
        file.write(program_content)
    print(f"Arquivo 'Program.cs' criado com sucesso em {program_path}")

# def create_docker_compose_file(project_name, database, db_user, db_password, db_name):
#     compose_content = f'''
# services:
#   postgres:
#     image: bitnami/postgresql:latest
#     ports:
#       - '5432:5432'
#     environment:
#       - POSTGRES_USER=postgres
#       - POSTGRES_PASSWORD=postgres
#       - POSTGRES_DB=teste
#     volumes:
#       - db_pg_data:/bitnami/postgresql
# volumes:
#   db_pg_data:
#     '''

#     compose_file_path = os.path.join(project_name, 'docker-compose.yml')
#     with open(compose_file_path, 'w') as file:
#         file.write(compose_content)
#     print(f"Arquivo 'docker-compose.yml' criado com sucesso em {compose_file_path}")




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
    create_auth_controller(args.projectName)
    create_user_model(args.projectName)
    create_user_login_dto(args.projectName)
    create_user_register_dto(args.projectName)
    create_application_db_context(args.projectName)
    create_encryption_service(args.projectName)
    create_appsettings_json(args.projectName, args.database, args.dbUser, args.dbPassword, args.dbName)
    create_program_cs(args.projectName, args.database)
    # ------------------------------------------------------
    
    add_project_dependencies(args.projectName, args.database)
    is_docker_installed()

    # Criar Docker Compose e Dockerfile
    create_docker_compose_file(args.projectName, args.database, args.dbUser, args.dbPassword, args.dbName)
    start_docker_compose(args.projectName)
    
    
    