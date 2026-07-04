"""Step definitions para gestión de reportes."""
from behave import given, when, then


@when("consulto la lista de reportes")
def step_listar_reportes(context):
    context.response = context.client.get("/reports/api")


@then("recibo una lista vacía")
def step_lista_vacia(context):
    assert context.response.status_code == 200
    assert context.response.json() == []


@given('he realizado un análisis de código "{codigo}"')
def step_realizar_analisis(context, codigo):
    r = context.client.post("/analyze/api", json={
        "target_type": "code",
        "target_value": codigo,
    })
    assert r.status_code == 200
    context.scan = r.json()


@when("consulto el reporte del último análisis")
def step_consultar_reporte(context):
    scan_id = context.scan["id"]
    context.response = context.client.get(f"/reports/api/{scan_id}")


@then("el reporte contiene el mismo score")
def step_mismo_score(context):
    assert context.response.status_code == 200
    assert context.response.json()["score"] == context.scan["score"]


@then("el reporte contiene los hallazgos")
def step_contiene_hallazgos(context):
    data = context.response.json()
    assert "findings" in data


@when("exporto el reporte en JSON")
def step_exportar_json(context):
    scan_id = context.scan["id"]
    context.response = context.client.get(f"/reports/{scan_id}/export-json")


@then('recibo un JSON con el campo "{campo}"')
def step_json_tiene_campo(context, campo):
    assert context.response.status_code == 200
    assert campo in context.response.json()


@when("consulto el reporte con ID {scan_id:d}")
def step_reporte_por_id(context, scan_id):
    context.response = context.client.get(f"/reports/api/{scan_id}")


@then("recibo un error 404")
def step_error_404(context):
    assert context.response.status_code == 404


@when('genero un token para el usuario "{usuario}"')
def step_generar_token(context, usuario):
    context.response = context.client.post("/api/token", data={"username": usuario})
    if context.response.status_code == 200:
        context.token = context.response.json()["token"]


@then("recibo un token válido")
def step_token_valido(context):
    assert context.response.status_code == 200
    assert "token" in context.response.json()


@then("puedo validar el token recibido")
def step_validar_token(context):
    r = context.client.get("/api/validate-token", headers={"x-api-key": context.token})
    assert r.status_code == 200
