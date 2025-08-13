# Honeypot XSS Logger con Ngrok

Este proyecto permite desplegar un **honeypot** en Kali Linux que, junto con **Ngrok**, expone públicamente un **payload XSS** para capturar credenciales y metadatos de usuarios que interactúen con una página vulnerable.

---

## 📂 Archivos del proyecto

| Archivo              | Descripción |
|----------------------|-------------|
| **`p.js`**           | Script JavaScript (payload) que se incrusta en la página vulnerable. Utiliza un nombre corto para cumplir con el límite de 50 caracteres en el campo de inyección. Muestra una interfaz falsa de login y envía las credenciales al servidor honeypot. |
| **`honeypot_logger.py`** | Script en Python que levanta un servidor HTTP en `localhost:8080` para recibir y registrar las credenciales enviadas por el payload. |
| **`honeypot_log.txt`**   | Archivo de logs donde se registran las interacciones con el honeypot, incluyendo:<br>• IP del cliente (extraída de `X-Forwarded-For`, `X-Real-IP` o `Forwarded`)<br>• User-Agent<br>• Campos enviados (usuario, contraseña, cookies, etc.) |

---

## 🚀 Ejecución

1. **Iniciar el honeypot local**  
   ```bash
   python3 honeypot_logger.py
   ```

2. **Exponer el puerto con Ngrok**  
   ```bash
   ngrok http 8080
   ```

3. **Obtener la URL pública** (Ejemplo)  
   ```
   Forwarding  https://b6b97a2903cc.ngrok-free.app -> http://localhost:8080
   ```

4. **Acortar la URL con TinyURL**  
   - Ir a [https://tinyurl.com/](https://tinyurl.com/)  
   - La URL corta **debe terminar con `/p.js`**.  
     Ejemplo:
     ```
     https://tinyurl.com/abcd123/p.js
     ```

5. **Actualizar el payload en el script de inyección**  
   - Abrir `XSS_Payload_Injection.py`  
   - Ir a la línea **1567** y reemplazar la URL antigua por la nueva URL corta.

---

## 📌 Notas importantes

- El servidor debe permanecer **activo** mientras se deseen capturar datos.
- Si Ngrok cambia la URL (por reinicio o reconexión), es necesario:
  1. Obtener el nuevo `forwarding`.
  2. Generar un nuevo **TinyURL**.
  3. Actualizarlo en `XSS_Payload_Injection.py`.

---

💡 **Recomendación**:  
Para mantener el payload siempre funcional, considera usar un subdominio dinámico o un servicio de túnel persistente para evitar tener que regenerar el enlace en cada reinicio.
