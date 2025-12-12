cmake_minimum_required(VERSION 3.10)
project(vulnscanner C)

# Archivos fuente
file(GLOB SRC
    "src/*.c"
)

# Incluye carpeta con headers
include_directories(include)

# Crear ejecutable
# Excluir el test de Winsock del ejecutable principal (tiene su propio `main`)
list(REMOVE_ITEM SRC ${CMAKE_SOURCE_DIR}/src/winsock_test.c)
add_executable(vulnscanner ${SRC})

# Si estamos en Windows, linkear WinSock2
if (WIN32)
    target_link_libraries(vulnscanner ws2_32)
endif()

# Ejecutable separado para el test de Winsock
if (WIN32)
    add_executable(winsock_test src/winsock_test.c)
    target_link_libraries(winsock_test ws2_32)
endif()
