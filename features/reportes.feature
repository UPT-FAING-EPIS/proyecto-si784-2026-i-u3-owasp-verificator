# language: es
Característica: Gestión de reportes de análisis
  Como usuario del verificador OWASP
  Quiero consultar y exportar reportes de análisis previos
  Para dar seguimiento a las vulnerabilidades detectadas

  Escenario: Listar reportes cuando no hay análisis
    Dado que el servicio está levantado
    Cuando consulto la lista de reportes
    Entonces recibo una lista vacía

  Escenario: Ver detalle de un reporte después de analizar
    Dado que el servicio está levantado
    Y he realizado un análisis de código "password = 'abc'"
    Cuando consulto el reporte del último análisis
    Entonces el reporte contiene el mismo score
    Y el reporte contiene los hallazgos

  Escenario: Exportar reporte en formato JSON
    Dado que el servicio está levantado
    Y he realizado un análisis de código "eval(data)"
    Cuando exporto el reporte en JSON
    Entonces recibo un JSON con el campo "scan_id"
    Y recibo un JSON con el campo "findings"

  Escenario: Consultar reporte inexistente
    Dado que el servicio está levantado
    Cuando consulto el reporte con ID 99999
    Entonces recibo un error 404

  Escenario: Generar y validar token API
    Dado que el servicio está levantado
    Cuando genero un token para el usuario "tester"
    Entonces recibo un token válido
    Y puedo validar el token recibido
