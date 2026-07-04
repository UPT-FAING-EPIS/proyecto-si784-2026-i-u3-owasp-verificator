# language: es
Característica: Análisis de seguridad de código
  Como usuario del verificador OWASP
  Quiero analizar código fuente en busca de vulnerabilidades
  Para conocer el nivel de cumplimiento de seguridad

  Escenario: Verificar que el servicio está operativo
    Dado que el servicio está levantado
    Cuando consulto el endpoint de salud
    Entonces recibo un estado "ok"

  Escenario: Analizar código con contraseña hardcodeada
    Dado que el servicio está levantado
    Cuando envío código con contenido "password = 'secret123'"
    Entonces el análisis se completa exitosamente
    Y el score es menor o igual a 100
    Y se detecta al menos 1 hallazgo
    Y se detecta la regla "OWASP-A02"

  Escenario: Analizar código con eval inseguro
    Dado que el servicio está levantado
    Cuando envío código con contenido "result = eval(user_input)"
    Entonces el análisis se completa exitosamente
    Y se detecta la regla "OWASP-A03"

  Escenario: Analizar código limpio sin vulnerabilidades obvias
    Dado que el servicio está levantado
    Cuando envío código con contenido "x = 1 + 2"
    Entonces el análisis se completa exitosamente
    Y el score es mayor o igual a 50

  Escenario: Rechazar tipo de análisis inválido
    Dado que el servicio está levantado
    Cuando envío un análisis con tipo "invalido" y valor "algo"
    Entonces recibo un error de validación
