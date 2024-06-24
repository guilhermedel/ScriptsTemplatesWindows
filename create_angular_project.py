import os
import sys
import argparse

def is_npm_installed():
    try:
        return_code = os.system('npm --version')
        if return_code != 0:
            print("O npm não está instalado ou não está no PATH.")
            sys.exit(1)
        print("O npm está instalado e configurado no PATH.")
    except Exception as e:
        print(f"Ocorreu um erro ao verificar a instalação do npm: {e}")
        sys.exit(1)

def is_angular_installed():
    try:
        return_code = os.system('ng version')
        if return_code != 0:
            return False
        print("O Angular CLI está instalado e configurado no PATH.")
        return True
    except Exception as e:
        print(f"Ocorreu um erro ao verificar a instalação do Angular CLI: {e}")
        sys.exit(1)

def install_angular():
    try:
        print("Instalando o Angular CLI...")
        return_code = os.system('npm install -g @angular/cli')
        if return_code != 0:
            print("Houve um erro na instalação do Angular CLI.")
            sys.exit(1)
        print("O Angular CLI foi instalado com sucesso.")
    except Exception as e:
        print(f"Ocorreu um erro ao instalar o Angular CLI: {e}")
        sys.exit(1)

def create_angular_project(project_name):
    try:
        print(f"Criando o projeto Angular '{project_name}'...")
        return_code = os.system(f'ng new {project_name} --no-standalone')
        if return_code != 0:
            print("Houve um erro na criação do projeto Angular.")
            sys.exit(1)
        print(f"O projeto Angular '{project_name}' foi criado com sucesso.")
    except Exception as e:
        print(f"Ocorreu um erro inesperado ao criar o projeto Angular: {e}")
        sys.exit(1)

def create_directories(project_name, directories):
    try:
        base_path = os.path.join(project_name, 'src', 'app')
        for directory in directories:
            os.makedirs(os.path.join(base_path, directory), exist_ok=True)
        print(f"As pastas {', '.join(directories)} foram criadas dentro de 'src/app'.")
    except Exception as e:
        print(f"Ocorreu um erro ao criar as pastas: {e}")
        sys.exit(1)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Cria um projeto Angular e pastas específicas dentro do projeto.')
    parser.add_argument('--projectName', type=str, required=True, help='Nome do projeto Angular a ser criado')
    parser.add_argument('--directories', nargs='+', default=['models', 'views', 'controllers'], help='Nomes das pastas a serem criadas dentro de src/app')

    args = parser.parse_args()

    is_npm_installed()
    
    if not is_angular_installed():
        install_angular()
    
    create_angular_project(args.projectName)
    create_directories(args.projectName, args.directories)
