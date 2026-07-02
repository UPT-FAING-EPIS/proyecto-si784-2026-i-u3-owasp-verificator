from app.services.scanner import calculate_score, scan_code


def test_scan_code_detects_risky_patterns():
    content = 'password = "abc123"\nvalue = eval(user_input)'
    findings = scan_code(content)

    rule_ids = {finding.rule_id for finding in findings}
    assert "OWASP-A02-HARDCODED-SECRET" in rule_ids
    assert "OWASP-A03-CODE-INJECTION" in rule_ids


def test_calculate_score_reduces_by_severity():
    content = 'password = "abc123"\nvalue = eval(user_input)'
    findings = scan_code(content)
    score = calculate_score(findings)

    # two high severity findings -> penalty 30+30 -> score 40 (weights: high=30)
    assert score == 40


def test_new_languages_rules():
    # Dockerfile root check
    docker_content = "FROM node:18\nUSER root\nCMD node index.js"
    findings_docker = scan_code(docker_content)
    assert any(f.rule_id == "OWASP-A05-DOCKER-ROOT" for f in findings_docker)

    # Open CIDR in config/terraform
    tf_content = 'resource "aws_security_group" "allow_all" { cidr_blocks = ["0.0.0.0/0"] }'
    findings_tf = scan_code(tf_content)
    assert any(f.rule_id == "OWASP-A01-OPEN-CIDR" for f in findings_tf)

    # Dynamic SQL in scripts
    sql_content = "DECLARE @q NVARCHAR(MAX); SET @q = 'SELECT * FROM users WHERE id = ' + @id; EXEC(@q);"
    findings_sql = scan_code(sql_content)
    assert any(f.rule_id == "OWASP-A03-DYNAMIC-SQL" for f in findings_sql)

    # K8s allow privilege escalation
    k8s_content = "securityContext:\n  allowPrivilegeEscalation: true"
    findings_k8s = scan_code(k8s_content)
    assert any(f.rule_id == "OWASP-A05-K8S-PRIV-ESC" for f in findings_k8s)
