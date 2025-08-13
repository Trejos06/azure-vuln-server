Honeypot XSS Logger con Ngrok

Este proyecto permite levantar un honeypot en Kali Linux que, combinado con Ngrok, hace visible un payload XSS en Internet para capturar credenciales y metadatos de usuarios que interactúen con él.
📂 Archivos del Proyecto

    p.js
    Script JavaScript (payload) que se incrusta en la página vulnerable.

        El nombre corto se utiliza para reducir el número de caracteres y ajustarse al límite de 50 caracteres permitido por el campo de inyección.

        El payload crea una interfaz falsa de login y envía las credenciales al servidor del honeypot.

    honeypot_logger.py
    Script en Python que levanta un servidor HTTP local en localhost:8080 para recibir y registrar las credenciales enviadas por el payload.

    honeypot_log.txt
    Archivo donde se almacenan los logs de los diferentes usuarios que han interactuado con el honeypot.
    Incluye:

        IP del cliente (obtenida de cabeceras X-Forwarded-For, X-Real-Ip o Forwarded)

        User-Agent

        Campos enviados (username, password, cookies, etc.)

🚀 Ejecución

    Iniciar el honeypot local

python3 honeypot_logger.py

Exponer el puerto con Ngrok

ngrok http 8080

Obtener la URL pública
Ejemplo:

Forwarding                    https://b6b97a2903cc.ngrok-free.app -> http://localhost:8080

Reducir la URL con TinyURL

    Usar: https://tinyurl.com/

    La URL corta debe terminar con /p.js
    Ejemplo:

        https://tinyurl.com/abcd123/p.js

    Actualizar el payload en el script de inyección
    En XSS_Payload_Injection.py, línea 1567, reemplazar la URL antigua por la nueva URL corta.

📌 Notas

    El servidor debe permanecer activo mientras se desee capturar datos.

    Si Ngrok cambia de URL (reinicio o reconexión), es necesario:

        Actualizar el forwarding.

        Generar un nuevo TinyURL.

        Reemplazarlo en XSS_Payload_Injection.py.
