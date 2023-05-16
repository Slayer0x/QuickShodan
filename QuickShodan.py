import shodan, os, time
# Ussage: Python3 QuickShodan.py
# Shodan API TOKEN
API_KEY = 'Your API Token'

def search_hosts(api):
    os.system('clear')
    query = input('Ingrese su consulta de búsqueda: ')
    try:
        # Realiza la búsqueda en Shodan
        results = api.search(query)

        print('\n\n')  
        os.system('clear')
        print(f'Se encontraron {str(results["total"])} resultados basados en la consulta: ' + str(query) + '.\n')
        
        print('##################### Inicio #####################')
        print('\n\n') 
        # Imprime los detalles de cada resultado
        for result in results['matches']:

            location = result.get('location')
            country_code = location.get('country_code')
            print('##################### Resultados del HOST: {}'.format(result['ip_str']) + ' #####################')

            print('\nIP: {}'.format(result['ip_str']))
            print(result['data'] + "\n[+] Open Ports: " + str(result['port']) + "\n[+] Country Code: "+ str(country_code) + "\n[+] OS: " + str(result['os']))
            print('')

        print('\n')  
        print('#####################  Fin #####################')
        print('\n')
        
    except shodan.APIError as e:
        print(f'\n Error: {e}') 
        print('\n')     

def get_host_info(api):
    os.system('clear')
    ip = input('Ingrese la dirección IP del host: ')
    try:
        # Detailed query
        host = api.host(ip)
        cve_results = host.get('vulns')

        print('\n\n')  
        print('##### Resultados de la búsqueda sobre el Host: ' + str(ip) + ' ######')
        print('\n')
        # Prints the results
        print(f'IP: {host["ip_str"]}')
        print(f'Open Ports: {host["ports"]}')
        print(f'Organization: {host["org"]}')
        print(f'Country: {host["country_name"]}')
        print('\n')
        if cve_results:
            print('Vulnerabilidades conocidas (CVE):\n')
            for cve in cve_results:
                print(f'- {cve}')
                
        else:
            print('No se encontraron vulnerabilidades conocidas (CVE) para este host.')

        print('\n')
        location = host["data"][0].get("location")
        if location:
            address = location.get("address")
            if address:
                print(f'Dirección: {address}\n')
            else:
                print('No se encontró la dirección en la estructura de datos.\n')
        else:
            print('No se encontró la ubicación en la estructura de datos.\n')
        print('\n')
        print(str('#' * 65))

    except shodan.APIError as e:
        print(f' \n Error: {e}')
        print('\n')

def main():
    # New Shodan API instance
    api = shodan.Shodan(API_KEY)
    
    print('''                                                                                                                                      
                                                                                        
                                                    *(####////,####)*                                  
                                            (#####(####(##########*                           
                                            ###(*,,,,,,,,,,,,,,/###*                        
                                        (##/,,,,,,,.    ,,,,,***(##.                      
                            .#############(,,,,,             ,*****##(                     
                        ###(/,,,,,,,,,,,,,,,,,                *****##                     
                    ,##(*,,,,,,,,,,,,,,,,,,,                 ,****(#(                    
                    ##(,,,,,,            ,,,,                 *////(#(                    
                    ##/,,,,,                ,**               */////##                     
                    ##(,,,,,                   ***.          ///////##                      
                    ##/,,,,                    ****///////////////##(     QuickShodan By @Slayer                  
                    ##/,,,,                    ///////////////(######.                      
                    ##*****                  /////(########(/**,,,*/((####/                
                    (##******              //////(####(*,,,,,,,,,,,,,,,,,/(###             
                    ##(******//.     /////////###(*,,,,,,,        .,,,,,,*/##(           
                        ###(*////////////////#####*,,,,,                .*****/##.         
                            #####((/////(#####.##(,,,,,                    ,*****##         
                                ./##(.       ##*,,,,                       ****(##        
                                            (#(,,,,.                       *****##        
                                            (#(,,,,,                       ////*##        
                                            ##/****                      /////(##        
                                            ,##*****,                   //////##         
                                                .##(******              .//////(##          
                                                (##(*****////*,.,//////////(##            
                                                    .###(*////////////////###(              
                                                        (######(((((######,                                                                                                 
    ''')

    while True:
        print('Opciones:')
        print('1. Búsqueda por software o Sistema Operativo.')
        print('2. Obtener información de un host.')
        print('3. Salir.')
        option = input('Seleccione una opción: ')
        
        if option == '1':
            search_hosts(api)
        elif option == '2':
            get_host_info(api)
        elif option == '3':
            print('\n')
            print('[+] Saliendo...')
            time.sleep(3)
            break
        else:
            print('Opción inválida. Por favor, seleccione una opción válida.\n')

if __name__ == '__main__':
    main()
