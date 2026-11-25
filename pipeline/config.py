"""Configuracion central: pesos, umbrales y SLA. Todo calibrable."""

PRIORITY_ORDER = {"P1": 1, "P2": 2, "P3": 3, "P4": 4, "N/A": 5}

# Pesos del score (suman 100 antes de bonus/multiplicadores)
W_SEVERITY = 20       # CVSS/10 * 20
W_EXPLOIT_KEV = 30    # en CISA KEV
W_EXPLOIT_PUBLIC = 25 # exploit publico conocido
W_EXPLOIT_EPSS_HIGH = 20  # EPSS >= 0.5
W_EXPLOIT_FLOOR = 5   # sin datos de explotacion
EXPOSURE = {True: 20, False: 8, None: 20}           # None = desconocido -> peor caso
ENVIRONMENT = {"production": 15, "staging": 6, "development": 2, "dev": 2, "test": 2, None: 15}
CONTEXT = {"reachable": 15, "runtime": 8, "build-only": 1}
BLAST_RADIUS_BONUS = 5

# Multiplicadores de contexto (superficie viva)
MULT_BUILD_ONLY = 0.5     # devDependency excluida del artefacto de produccion
MULT_NOT_RUNNING = 0.3    # runningTasks == 0: no hay superficie viva hoy

THRESHOLDS = [(80, "P1"), (60, "P2"), (35, "P3"), (0, "P4")]

SLA = {"P1": "24h", "P2": "7d", "P3": "30d", "P4": "90d", "N/A": "cierre documentado (revision a 180d)"}

LINUX_DISTROS = ("debian", "ubuntu", "alpine", "rhel", "centos", "rocky", "alma",
                 "amazonlinux", "amzn", "fedora", "suse", "opensuse", "wolfi", "distroless")
CROSS_PLATFORM_ECOSYSTEMS = ("npm", "pypi", "maven", "go", "cargo", "rubygems", "nuget", "composer")

PROMPT_VERSION = "triage-agent/v1.0"
