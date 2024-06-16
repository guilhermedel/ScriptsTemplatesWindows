# Verifica se um nome de projeto foi passado como parâmetro
param (
    [string]$projectName,
    [string[]]$additionalFolders = @("Models", "Services", "Utils", "Controllers", "Data", "Dtos"),
    [string]$template = ""
)

# Verifica se o parâmetro foi fornecido
if (-not $projectName) {
    Write-Host "Erro: Você deve fornecer um nome para o projeto."
    exit 1
}

# Executa o comando para criar o projeto Web API
Write-Host "Criando projeto Web API com o nome: $projectName"
dotnet new webapi -n $projectName


# Verifica se o comando foi executado com sucesso
if ($LASTEXITCODE -eq 0) {

    Write-Host "Projeto criado com sucesso!"

    # Define o caminho do diretório do projeto
    $projectPath = Join-Path -Path (Get-Location) -ChildPath $projectName
    dotnet add $projectPath package Microsoft.EntityFrameworkCore
    dotnet add $projectPath package Npgsql.EntityFrameworkCore.PostgreSQL
    dotnet add $projectPath package Microsoft.AspNetCore.Authentication.JwtBearer
    dotnet add $projectPath package Swashbuckle.AspNetCore
    dotnet add $projectPath package Microsoft.EntityFrameworkCore.Design
    # Cria as pastas especificadas
    foreach ($folder in $additionalFolders) {
        $folderPath = Join-Path -Path $projectPath -ChildPath $folder
        if (-not (Test-Path -Path $folderPath)) {
            New-Item -Path $folderPath -ItemType Directory
            Write-Host "Pasta criada: $folderPath"
        }
        else {
            Write-Host "Pasta já existe: $folderPath"
        }
    }

    if ($template -eq "auth") {
        $authFolderPath = Join-Path -Path $projectPath -ChildPath "Services"
        $authFilePath = Join-Path -Path $authFolderPath -ChildPath "AuthService.cs"
        $authInterfaceFilePath = Join-Path -Path $authFolderPath -ChildPath "IAuthService.cs"
        $controllerFolderPath = Join-Path -Path $projectPath -ChildPath "Controllers"
        $authControllerFilePath = Join-Path -Path $controllerFolderPath -ChildPath "AuthController.cs"
        $modelsFolderPath = Join-Path -Path $projectPath -ChildPath "Models"
        $userModelFilePath = Join-Path -Path $modelsFolderPath -ChildPath "User.cs"
        $dtosFolderPath = Join-Path -Path $projectPath -ChildPath "Dtos"
        $userLoginDtoFilePath = Join-Path -Path $dtosFolderPath -ChildPath "UserLoginDto.cs"
        $userRegisterDtoFilePath = Join-Path -Path $dtosFolderPath -ChildPath "UserRegisterDto.cs"

        $dbContextContent = @"
using Microsoft.EntityFrameworkCore;
using $projectName.Models;

namespace $projectName.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
        }

        public DbSet<User> Users { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Configurações adicionais de modelos
        }
    }
}
"@

        # Define o caminho do arquivo ApplicationDbContext.cs
        $dbContextFilePath = Join-Path -Path $projectPath -ChildPath "Data/ApplicationDbContext.cs"

        # Salva o conteúdo no arquivo ApplicationDbContext.cs, sobrescrevendo se existir
        $dbContextContent | Out-File -FilePath $dbContextFilePath -Encoding utf8 -Force

        $authControllerContent = @"
using Microsoft.AspNetCore.Mvc;
using $projectName.Dtos;
using $projectName.Services;

namespace $projectName.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] UserLoginDto userLoginDto)
        {
            var token = _authService.Authenticate(userLoginDto);

            if (token == null)
                return Unauthorized();

            return Ok(new { Token = token });
        }
    }
}
"@

        # Define o caminho do arquivo AuthController.cs
        $authControllerFilePath = Join-Path -Path $controllerFolderPath -ChildPath "AuthController.cs"

        # Salva o conteúdo no arquivo AuthController.cs, sobrescrevendo se existir
        $authControllerContent | Out-File -FilePath $authControllerFilePath -Encoding utf8 -Force

        # UserController
        $userControllerContent = @"
using Microsoft.AspNetCore.Mvc;
using $projectName.Dtos;
using $projectName.Services;

namespace $projectName.Controllers
{
    [Route("users")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IAuthService _authService;

        public UserController(IAuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] UserRegisterDto userRegisterDto)
        {
            var user = await _authService.Register(userRegisterDto);
            if (user == null)
                return BadRequest("Registration failed. Email may already be in use.");
            
            return Ok(user);
        }
    }
}
"@

        # Define o caminho do arquivo UserController.cs
        $userControllerFilePath = Join-Path -Path $controllerFolderPath -ChildPath "UserController.cs"

        # Salva o conteúdo no arquivo UserController.cs, sobrescrevendo se existir
        $userControllerContent | Out-File -FilePath $userControllerFilePath -Encoding utf8 -Force
        # Define o conteúdo do IAuthService.cs
        $authInterfaceContent = @"
using $projectName.Dtos;
using $projectName.Models;

namespace $projectName.Services
{
    public interface IAuthService
    {
        Task<bool> Authenticate(string email,string password);
        Task<User> Register(UserRegisterDto userRegisterDto);
    }
}
"@

        # Define o caminho do arquivo IAuthService.cs
        $authInterfaceFilePath = Join-Path -Path $authFolderPath -ChildPath "IAuthService.cs"

        # Salva o conteúdo no arquivo IAuthService.cs, sobrescrevendo se existir
        $authInterfaceContent | Out-File -FilePath $authInterfaceFilePath -Encoding utf8 -Force

        # Define o conteúdo do AuthService.cs
        $authContent = @"
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using $projectName.Dtos;
using $projectName.Models;
using $projectName.Utils.Encryption;
using $projectName.Data;
using Microsoft.EntityFrameworkCore;

namespace $projectName.Services
{
    public class AuthService : IAuthService
    {
        private readonly List<User> _users = new List<User>();
        private readonly string _key;

        private readonly ApplicationDbContext _context;

        public AuthService(ApplicationDbContext context,IConfiguration configuration)
        {
            _context = context;
            _key = configuration["Jwt:Key"];
        }

       public async Task<bool> Authenticate(string email,string password)
        {
            User user = await _context.Users.FirstOrDefaultAsync(u => u.Email.Equals(email));
            if (user == null) return false;

            return EncryptionService.VerifyPassword(password, user.Password);
        }

        public async Task<User> Register(UserRegisterDto userRegisterDto)
        {
            if (await _context.Users.AnyAsync(u => u.Email == userRegisterDto.Email))
                return null;

            var newUser = new User
            {
                Cpf = userRegisterDto.Cpf,
                Name = userRegisterDto.Name,
                Email = userRegisterDto.Email,
                Password = EncryptionService.EncryptPassword(userRegisterDto.Password),
                Phone = userRegisterDto.Phone,
                BirthdayDate = DateTime.SpecifyKind(userRegisterDto.BirthdayDate, DateTimeKind.Utc)
            };

            _context.Users.AddAsync(newUser);
            await _context.SaveChangesAsync();

            return newUser;
        }
    }
}
"@

        # Define o caminho do arquivo AuthService.cs
        $authFilePath = Join-Path -Path $authFolderPath -ChildPath "AuthService.cs"

        # Salva o conteúdo no arquivo AuthService.cs, sobrescrevendo se existir
        $authContent | Out-File -FilePath $authFilePath -Encoding utf8 -Force

        # Define o conteúdo do User.cs
        $userModelContent = @"
namespace $projectName.Models
{
    public class User
    {
        [Key]
        public Guid Id { get; set; }
        public string Cpf { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string Phone { get; set; }
        public DateTime BirthdayDate { get; set; }

        public User(string name, string email, string phone, string cpf,string password,DateTime birthdayDate)
        {
            Id = new Guid();
            Cpf = cpf;
            Name = name;
            Email = email;
            Password=password;
            Phone = phone;
            BirthdayDate = birthdayDate; 
        }
    }
}
"@

        # Define o caminho do arquivo User.cs
        $userModelFilePath = Join-Path -Path $modelsFolderPath -ChildPath "User.cs"

        # Salva o conteúdo no arquivo User.cs, sobrescrevendo se existir
        $userModelContent | Out-File -FilePath $userModelFilePath -Encoding utf8 -Force

        # Define o conteúdo do UserLoginDto.cs
        $userLoginDtoContent = @"
namespace $projectName.Dtos
{
    public class UserLoginDto
    {
        public string Email { get; set; }
        public string Password { get; set; }
    }
}
"@

        # Define o caminho do arquivo UserLoginDto.cs
        $userLoginDtoFilePath = Join-Path -Path $dtosFolderPath -ChildPath "UserLoginDto.cs"

        # Salva o conteúdo no arquivo UserLoginDto.cs, sobrescrevendo se existir
        $userLoginDtoContent | Out-File -FilePath $userLoginDtoFilePath -Encoding utf8 -Force

        # Define o conteúdo do UserRegisterDto.cs
        $userRegisterDtoContent = @"
using System;

namespace $projectName.Dtos
{
    public class UserRegisterDto
    {
        public string Cpf { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string Phone { get; set; }
        public DateTime BirthdayDate { get; set; }
    }
}
"@

        # Define o caminho do arquivo UserRegisterDto.cs
        $userRegisterDtoFilePath = Join-Path -Path $dtosFolderPath -ChildPath "UserRegisterDto.cs"

        # Salva o conteúdo no arquivo UserRegisterDto.cs, sobrescrevendo se existir
        $userRegisterDtoContent | Out-File -FilePath $userRegisterDtoFilePath -Encoding utf8 -Force


        $encryptionServiceContent = @"
    using System;
    using System.IdentityModel.Tokens.Jwt;
    using System.Security.Claims;
    using System.Security.Cryptography;
    using System.Text;
    using Microsoft.IdentityModel.Tokens;

    namespace $projectName.Utils.Encryption
    {
        public static class EncryptionService
        {
            public static string GenerateToken(string email)
            {
                var builder = WebApplication.CreateBuilder();
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(builder.Configuration["Jwt:Key"]);
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new Claim[] { new Claim(ClaimTypes.Name, email) }),
                    Expires = DateTime.UtcNow.AddDays(1),
                    SigningCredentials = new SigningCredentials(
                        new SymmetricSecurityKey(key),
                        SecurityAlgorithms.HmacSha256
                    )
                };
                var token = tokenHandler.CreateToken(tokenDescriptor);
                return tokenHandler.WriteToken(token);
            }

            public static string EncryptPassword(string password)
            {
                using (SHA256 sha256Hash = SHA256.Create())
                {
                    byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(password));
                    // Convert byte array to a string representation
                    StringBuilder builder = new();
                    for (int i = 0; i < bytes.Length; i++)
                    {
                        builder.Append(bytes[i].ToString("x2"));
                    }
                    return builder.ToString();
                }
            }

            public static bool VerifyPassword(string password, string hash)
            {
                string inputHash = EncryptPassword(password);
                return inputHash.Equals(hash, StringComparison.OrdinalIgnoreCase);
            }
        }
    }
"@

        # Caminho completo do arquivo
        $encryptionServicePath = "$projectName\Utils\EncryptionService.cs"

        # Salva o conteúdo no arquivo
        $encryptionServiceContent | Out-File -FilePath $encryptionServicePath



        # Define o conteúdo do appsettings.json
        $appSettingsContent = @"
{
  "ConnectionStrings": {
    "DefaultConnection": "Host=localhost;Port=5432;Database=my_database;Username=my_username;Password=my_password;"
  },
  "Jwt": {
    "Key": "s4l0nK3yf0r3ncryptTh3s3P4ss0w0rdN33dM0r3Ch4r4ct3rs"
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft": "Warning",
      "Microsoft.Hosting.Lifetime": "Information"
    }
  },
  "AllowedHosts": "*"
}
"@

        # Define o caminho do arquivo appsettings.json
        $appSettingsFilePath = Join-Path -Path $projectPath -ChildPath "appsettings.json"

        # Salva o conteúdo no arquivo appsettings.json, sobrescrevendo se existir
        $appSettingsContent | Out-File -FilePath $appSettingsFilePath -Encoding utf8 -Force


        $programContent = @"
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using $projectName.Data;
using $projectName.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var key = Encoding.ASCII.GetBytes(builder.Configuration["Jwt:Key"]);

// Configurar JWT
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = false,
        ValidateAudience = false
    };
});

builder.Services.AddScoped<IAuthService, AuthService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

"@

        # Define o caminho do arquivo Program.cs
        $programFilePath = Join-Path -Path $projectPath -ChildPath "Program.cs"

        # Salva o conteúdo no arquivo Program.cs
        $programContent | Out-File -FilePath $programFilePath -Encoding utf8 -Force

        $authControllerContent = @"
using Microsoft.AspNetCore.Mvc;
using $projectName.Dtos;
using $projectName.Services;
using $projectName.Utils.Encryption;
using System.Text;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace $projectName.Controllers
{
    [Route("users")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        [HttpGet("login")]
        public async Task<IActionResult> Login()
        {
            try
            {
                var authHeader = AuthenticationHeaderValue.Parse(Request.Headers["Authorization"]);

                if (authHeader.Scheme is not "Basic")
                    return Unauthorized("ASDasD");

                var credentials = Encoding.ASCII.GetString(
                    Convert.FromBase64String(authHeader.Parameter)
                );
                var separatorIndex = credentials.IndexOf(':');
                string email = credentials.Substring(0, separatorIndex);
                string password = credentials.Substring(separatorIndex + 1);


                bool isLoginValid = await _authService.Authenticate(email,password);
                if (!isLoginValid)
                    return NotFound("Login inválido.");


                string token = EncryptionService.GenerateToken(email);

                return Ok(new { Token = token });
            }
            catch (Exception e)
            {
                return BadRequest(e.Message);
            }
        }
    }
}
"@

        # Define o caminho do arquivo AuthController.cs
        $authControllerFilePath = Join-Path -Path $controllerFolderPath -ChildPath "AuthController.cs"

        # Salva o conteúdo no arquivo AuthController.cs, sobrescrevendo se existir
        $authControllerContent | Out-File -FilePath $authControllerFilePath -Encoding utf8 -Force

        # Define o conteúdo do User.cs
        $userModelContent = @"
namespace $projectName.Models
{
    public class User
    {
        public int Id { get; set; }
        public string Cpf { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string Phone { get; set; }
        public DateTime BirthdayDate { get; set; }
    }
}
"@

        # Define o caminho do arquivo User.cs
        $userModelFilePath = Join-Path -Path $modelsFolderPath -ChildPath "User.cs"

        # Salva o conteúdo no arquivo User.cs, sobrescrevendo se existir
        $userModelContent | Out-File -FilePath $userModelFilePath -Encoding utf8 -Force

        # Define o conteúdo do UserLoginDto.cs
        $userLoginDtoContent = @"
namespace $projectName.Dtos
{
    public class UserLoginDto
    {
        public string Email { get; set; }
        public string Password { get; set; }
    }
}
"@

        # Define o caminho do arquivo UserLoginDto.cs
        $userLoginDtoFilePath = Join-Path -Path $dtosFolderPath -ChildPath "UserLoginDto.cs"

        # Salva o conteúdo no arquivo UserLoginDto.cs, sobrescrevendo se existir
        $userLoginDtoContent | Out-File -FilePath $userLoginDtoFilePath -Encoding utf8 -Force

        # Define o conteúdo do UserRegisterDto.cs
        $userRegisterDtoContent = @"
using System;

namespace $projectName.Dtos
{
    public class UserRegisterDto
    {
        public string Cpf { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string Phone { get; set; }
        public DateTime BirthdayDate { get; set; }
    }
}
"@

        # Define o caminho do arquivo UserRegisterDto.cs
        $userRegisterDtoFilePath = Join-Path -Path $dtosFolderPath -ChildPath "UserRegisterDto.cs"

        # Salva o conteúdo no arquivo UserRegisterDto.cs, sobrescrevendo se existir
        $userRegisterDtoContent | Out-File -FilePath $userRegisterDtoFilePath -Encoding utf8 -Force
    }

}




else {
    Write-Host "Erro ao criar o projeto."
    exit $LASTEXITCODE
}
