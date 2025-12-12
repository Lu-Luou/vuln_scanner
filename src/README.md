# Archivos src/

Pensé en usar una estructura sencilla modular donde el main.c controla todo el flujo del programa. Empezando por un escaneo de la red y los puertos del dispositivo local donde se ejecuta, para luego analizar la info y mostrarla en pantalla.

## Flujo

Acá separo en 3 grupos de archivos:

### main.c / utils.c / config.c

Encargados de hacer de nexo entre la parte lógica y analítica del proyecto, sería el esqueleto de todo el proyecto. Utils.c tiene funciones comunes y config.c lo voy a utilizar como capa de abstracción entre windows (Win10) y linux(Mint - Ubuntu).

### scannerIP.c y network.c

Encargados de las APIs de red (por ahora WinSock) y de consultar datos para encontrar conexiones raras y puertos abiertos.

### analysis.c

Encargado del procesamiento y muestra de los datos para que el usuario esté al día de lo que pasa por su dispositivo.
