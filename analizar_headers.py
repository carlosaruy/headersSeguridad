import requests
import argparse
import urllib3

def mostrar(response):
    print(f"Headers analizados:")
    print(f"-------------------")
    for key, value in response.headers.items():
        print(f"{key}: {value}")

def evaluar_cabeceras(url, verify_ssl,verbose):
    response = requests.get(url, verify=verify_ssl)
    headers = response.headers
    
    print(f"Analizando las cabeceras de {url}:")
    
    # Ausencia de HSTS
    if 'Strict-Transport-Security' not in headers:
        print("  - Recomendación: Implementar HSTS.")
        if verbose >= 1: 
            print("  +   dado que no se encontró el header Strict-Transport-Security")
        if verbose >= 2:
            print("  +    Indica que el sitio no está forzando conexiones HTTPS, debilidad de MiTM.")

    
    # Ausencia de CSP
    if 'Content-Security-Policy' not in headers:
        print("  - Recomendación: Configurar CSP para prevenir ataques como inyección de código y XSS.")
        if verbose >= 1:
            print("  +   dado que no se encontró el header Content-Security-Policy")
        if verbose >= 2:
            print("  +    Permite una amplia variedad de ataques, como inyección de código y XSS, ya que no hay restricciones sobre las fuentes de contenido.")
    
    # Sitio embebible en sitios de terceros
    if headers.get('X-Frame-Options') not in ['SAMEORIGIN', 'DENY']:
        print("  - Recomendación: Configurar 'X-Frame-Options' para proteger contra clickjacking.")
        if verbose >= 1:
            print("  +   dado que no se encontró el header X-Frame-Options")
        if verbose >= 2:
            print("  +    Hace que el sitio sea vulnerable a ataques de clickjacking, ya que puede ser enmarcado por sitios de terceros.")
     
    # Content-Type no forzado
    if headers.get('X-Content-Type-Options') != 'nosniff':
        print("  - Recomendación: Agregar 'X-Content-Type-Options: nosniff' para prevenir sniffing de MIME.")
        if verbose >= 1:
            print("  +   dado que no se encontró el header X-Content-Type-Options:")
        if verbose >= 2:
            print("  +    Permite que los navegadores intenten interpretar el tipo de contenido, lo que podría llevar a ataques basados en el sniffing de MIME.")

    # Ausencia de política de Referrer
    if 'Referrer-Policy' not in headers:
        print("  - Recomendación: Establecer una política de Referrer adecuada.")
        if verbose >= 1:
            print("  +   dado que no se encontró el header Referrer-Policy:")
        if verbose >= 2:
            print("  +    Puede exponer información sensible a través de la URL, ya que los navegadores pueden enviar la URL completa como referente a otros sitios.")
   
    # Ausencia de política de permisos
    if 'Permissions-Policy' not in headers:
        print("  - Recomendación: Configurar 'Permissions-Policy' para controlar el acceso a funciones del navegador.")
        if verbose >= 1:
            print("  +   dado que no se encontró el header Permissions-Policy:")
        if verbose >= 2:
            print("  +    Sin este header, los sitios web pueden acceder a ciertas funciones del navegador (como la cámara o la ubicación) sin restricciones, lo que podría conducir a problemas de privacidad.")
    
    # Información sensible del servidor, solo ejemplo.  
    if 'Server' in headers:
        print("  - Consideración: Ocultar o modificar información del servidor para no revelar datos innecesarios.")
        if verbose >= 1:
            print("  +   dado que se encontró este header: " , headers['Server'])
        if verbose >= 2:
            print("  +    Divulgar esta información podría darle mas oportunidades al atacante para aprovecharlas.")

    mostrar(response)

def main():
    parser = argparse.ArgumentParser(description="Analiza las cabeceras HTTP de una URL y proporciona recomendaciones de seguridad.")
    parser.add_argument("url", help="La URL del sitio web que desea analizar. Asegúrate de incluir 'http://' o 'https://'.")
    parser.add_argument("-k", "--insecure", action="store_false", help="Desactiva la verificación SSL (inseguro).", dest="verify_ssl")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Modo detallado. Agrega más 'v' para mayor detalle (por ejemplo, -vv).") 

    args = parser.parse_args()

    # Comprobando si la URL proporcionada comienza con http:// o https://
    if not args.url.startswith(('http://', 'https://')):
        print("Error: La URL debe comenzar con 'http://' o 'https://'.")
        return
    if not args.verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        print("Advertencia: La verificación SSL está desactivada. La conexión no es segura.")

    evaluar_cabeceras(args.url, args.verify_ssl, args.verbose)

if __name__ == "__main__":
    main()
