cmake_minimum_required(VERSION 3.10)
project(vulnscanner C)

# Archivos fuente
file(GLOB SRC
    "src/*.c"
)

# Incluye carpeta con headers
include_directories(include)

# Crear ejecutable
add_executable(vulnscanner ${SRC})

# Si estamos en Windows, linkear WinSock2
if (WIN32)
    target_link_libraries(vulnscanner ws2_32)
endif()
