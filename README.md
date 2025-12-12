# Vulnscanner simple y en C usando "GPT-5.1 Codex"

```txt
+-------------------------------------------------------+
|                    VULN SCANNER                       |
+First stage--------------------------------------------+
|                                                       |
|  +------------------------+       +---------------+   |
|  |   Input / CLI Parser   | ----> |  Config Core  |   |
|  +------------------------+       +---------------+   |
|            |                                 |        |
|            v                                 v        |
|  +------Threads-------+            +----------------+ |
|  |  Port Scanner      |<---------->| Network Utils  | |
|  |  - TCP Scan        |            | - Raw sockets  | |
|  |  - SYN Scan        |            | - Packet forge | |
|  |  - UDP Scan        |            | - Timeouts     | |
|  +--------------------+            +----------------+ |
|            |                                 |        |
|            v                                 v        |
|  +------Threads-------+ Analysis.c +----------------+ |
|  |  Web Scanner       |<---------->| HTTP Client    | |
|  |  - Dir fuzzing     |            | - GET/POST     | |
|  |  - XSS tests       |            | - Headers      | |
|  |  - SQL tests       |            | - Cookies      | |
|  +--------------------+            +----------------+ |
|            |                                 |        |
|            +------------+         +-----------+       |
|                         |         |                   |
+Second stage-------------|---------|-------------------+
|                         v         v                   |
|            +---------------------------------------+  |
|            |         Vulnerability Engine          |  |
|            |  - Reglas (XSS, SQLi, ports, CMS)     |  |
|            |  - Fingerprinting (OS/CMS)            |  |
|            |  - Scoring de riesgo                  |  |
|            +---------------------------------------+  |
|                         |         |                   |
|                         v         v                   |
|            +------MAYBE-----+   +------------------+  |
|            |  Threat Intel  |   |    Reporting     |  |
|            | - Blacklists   |   | - JSON/HTML logs |  |
|            | - IOC feeds    |   | - Summary CVSS   |  |
|            +----------------+   +------------------+  |
|                         \         /                   |
|                          \       /                    |
|                          +MAYBE+                      |
|                          | TUI |                      |
|                          +-----+                      |
+-------------------------------------------------------+
```
