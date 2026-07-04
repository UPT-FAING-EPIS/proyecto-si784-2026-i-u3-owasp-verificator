"""Step definitions para análisis de seguridad."""
from behave import given, when, then


@given("que el servicio está levantado")
def step_servicio_levantado(context):
    r = context.client.get("/health")
    assert r.status_code == 200


@when('consulto el endpoint de salud')
def step_consultar_health(context):
    context.response = context.client.get("/health")


@then('recibo un estado "{estado}"')
def step_verificar_estado(context, estado):
    assert context.response.json()["status"] == estado


@when('envío código con contenido "{codigo}"')
def step_enviar_codigo(context, codigo):
    payload = {"target_type": "code", "target_value": codigo}
    context.response = context.client.post("/analyze/api", json=payload)
    if context.response.status_code == 200:
        context.scan = context.response.json()


@then("el análisis se completa exitosamente")
def step_analisis_exitoso(context):
    assert context.response.status_code == 200
    assert context.scan is not None


@then("el score es menor o igual a {valor:d}")
def step_score_menor_igual(context, valor):
    assert context.scan["score"] <= valor


@then("el score es mayor o igual a {valor:d}")
def step_score_mayor_igual(context, valor):
    assert context.scan["score"] >= valor


@then("se detecta al menos {cantidad:d} hallazgo")
def step_detectar_hallazgos(context, cantidad):
    assert len(context.scan["findings"]) >= cantidad


@then('se detecta la regla "{regla}"')
def step_detectar_regla(context, regla):
    rule_ids = {f["rule_id"] for f in context.scan["findings"]}
    assert any(rid.startswith(regla) for rid in rule_ids), f"Regla {regla} no encontrada en {rule_ids}"



@when('envío un análisis con tipo "{tipo}" y valor "{valor}"')
def step_enviar_tipo_invalido(context, tipo, valor):
    payload = {"target_type": tipo, "target_value": valor}
    context.response = context.client.post("/analyze/api", json=payload)


@then("recibo un error de validación")
def step_error_validacion(context):
    assert context.response.status_code == 422
