import requests
import argparse
import urllib3

def mostrar(response):
    print(f"Headers analizados:")
    print(f"-------------------")
    for key, value in response.headers.items():
        print(f"{key}: {value}")

def evaluar_cabeceras(url, verify_ssl):
    response = requests.get(url, verify=verify_ssl)
    headers = response.headers
    
    print(f"Analizando las cabeceras de {url}:")
    
    # Ausencia de HSTS
    if 'Strict-Transport-Security' not in headers:
        print("  - Recomendación: Implementar HSTS.")
    
    # Ausencia de CSP
    if 'Content-Security-Policy' not in headers:
        print("  - Recomendación: Configurar CSP para prevenir ataques como inyección de código y XSS.")
    
    # Sitio embebible en sitios de terceros
    if headers.get('X-Frame-Options') not in ['SAMEORIGIN', 'DENY']:
        print("  - Recomendación: Configurar 'X-Frame-Options' para proteger contra clickjacking.")
    
    # Content-Type no forzado
    if headers.get('X-Content-Type-Options') != 'nosniff':
        print("  - Recomendación: Agregar 'X-Content-Type-Options: nosniff' para prevenir sniffing de MIME.")
    
    # Ausencia de política de Referrer
    if 'Referrer-Policy' not in headers:
        print("  - Recomendación: Establecer una política de Referrer adecuada.")
    
    # Ausencia de política de permisos
    if 'Permissions-Policy' not in headers:
        print("  - Recomendación: Configurar 'Permissions-Policy' para controlar el acceso a funciones del navegador.")
    
    # Información sensible del servidor, solo ejemplo.  
    if 'Server' in headers:
        print("  - Consideración: Ocultar o modificar información del servidor para no revelar datos innecesarios.")
    mostrar(response)

def main():
    parser = argparse.ArgumentParser(description="Analiza las cabeceras HTTP de una URL y proporciona recomendaciones de seguridad.")
    parser.add_argument("url", help="La URL del sitio web que desea analizar. Asegúrate de incluir 'http://' o 'https://'.")
    parser.add_argument("-k", "--insecure", action="store_false", help="Desactiva la verificación SSL (inseguro).", dest="verify_ssl")
    args = parser.parse_args()

    # Comprobando si la URL proporcionada comienza con http:// o https://
    if not args.url.startswith(('http://', 'https://')):
        print("Error: La URL debe comenzar con 'http://' o 'https://'.")
        return
    if not args.verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        print("Advertencia: La verificación SSL está desactivada. La conexión no es segura.")

    evaluar_cabeceras(args.url, args.verify_ssl)

if __name__ == "__main__":
    main()