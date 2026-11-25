# ① Diagrama del pipeline

![Diagrama de arquitectura del pipeline](01_diagrama.png)

> Formatos listos para entrega: [PNG alta resolución](01_diagrama.png) · [SVG vectorial](01_diagrama.svg) · Fuente editable Mermaid abajo.

```mermaid
flowchart TD
    subgraph SRC["Escaneres"]
        S1["dependency-scanner<br/>(npm / pypi)"]
        S2["SAST<br/>(codigo propio)"]
        S3["container-scanner<br/>(imagenes)"]
        S4["host-scanner<br/>(servidores)"]
    end

    S1 & S2 & S3 & S4 -- "Prod: HTTPS TLS 1.3 + mTLS/OIDC/HMAC" --> N["1. Ingesta + normalizacion<br/>esquema unico, SHA-256"]
    N --> SAN["2. Sanitizacion<br/>texto libre = DATO no confiable<br/>detector de prompt injection"]
    SAN --> EN["3. Enriquecimiento<br/>CMDB: dueno, entorno, exposicion<br/>EPSS / CISA KEV"]
    EN --> DD["4. Dedup + causa raiz<br/>CVE+paquete+version<br/>imagen base = unidad de fix"]
    DD --> AP{"5. Aplica a Linux?<br/>solo evidencia ESTRUCTURADA"}
    AP -- "No (campo estructurado)" --> NA["Cierre N/A documentado<br/>revision a 180 dias"]
    AP -- "Si / dudoso" --> SC["6. Score determinista + reglas duras<br/>P1 24h / P2 7d / P3 30d / P4 90d"]
    SC --> AI["IA acotada (Gemini)<br/>resume, redacta PR, sugiere<br/>solo puede SUBIR o pedir revision"]
    AI --> GR{"Guardrails<br/>esquema, sin downgrade,<br/>sin versiones inventadas"}
    GR --> RT{"7. Tipo"}

    RT -- "Codigo: dependencia" --> C1["PR automatico con fixedVersion<br/>CI + re-escaneo"]
    C1 --> C2{"devDependency +<br/>patch/minor + P3/P4?"}
    C2 -- Si --> C3["Auto-merge si CI verde"]
    C2 -- No --> H1(["Humano: Team Lead del repo<br/>+ AppSec si major o tampering"])
    RT -- "Codigo: SAST" --> C4["Ticket + draft PR por IA"] --> H2(["Humano: Team Lead + AppSec"])

    RT -- "SO: imagen base" --> O1["PR al Dockerfile base<br/>1 ticket de plataforma"] --> H3(["Humano: DevOps aprueba<br/>rollout canary -> resto"])
    H3 --> O2["Rebuild de imagenes hijas"]
    RT -- "SO: sin tareas vivas" --> O3["Bloquear redeploy (admision)<br/>proponer retiro"] --> H4(["Humano: dueno confirma"])
    RT -- "SO: kernel / hosts" --> O4["Ticket"] --> H5(["Humano: DevOps<br/>ventana de mantenimiento"])

    C3 & H1 & H2 & O2 & H4 & H5 --> V["8. Re-escaneo por instancia"]
    V -- "persiste" --> ESC["SLA vencido -> escalamiento"]
    ESC --> SC
    V -- "desaparecio" --> CL["Cierre"]

    SAN -. "tampering_suspected" .-> H0(["AppSec: alerta de manipulacion"])
    N & SAN & EN & DD & SC & GR & CL -.-> AUD[("Log de auditoria<br/>append-only, cadena de hashes")]

    subgraph PREV["Prevencion (antes del hallazgo)"]
        P1["Gate en CI: falla si entra P1/P2"]
        P2["Admision en cluster: bloquea imagenes con criticos con fix"]
        P3["Renovate + imagenes base golden con rebuild semanal"]
    end
    PREV -. "reduce entrada" .-> SRC
```

**Leyenda:** rectangulos = pasos automaticos · rombos = decisiones del motor · ovalos = intervencion humana.
