# Vulnscanner simple y en C

```txt
+-------------------------------------------------------+
|                    VULN SCANNER                       |
+-------------------------------------------------------+
|                                                       |
|  +------------------------+       +---------------+   |
|  |   Input / CLI Parser   | ----> |  Config Core  |   |
|  +------------------------+       +---------------+   |
|            |                                 |        |
|            v                                 v        |
|  +--------------------+            +----------------+ |
|  |  Port Scanner      |<---------->| Network Utils  | |
|  |  - TCP Scan        |            | - Raw sockets  | |
|  |  - SYN Scan        |            | - Packet forge | |
|  |  - UDP Scan        |            | - Timeouts     | |
|  +--------------------+            +----------------+ |
|            |                                 |        |
|            v                                 v        |
|  +--------------------+            +----------------+ |
|  |  Web Scanner       |<---------->| HTTP Client    | |
|  |  - Dir fuzzing     |            | - GET/POST     | |
|  |  - XSS tests       |            | - Headers      | |
|  |  - SQL tests       |            | - Cookies      | |
|  +--------------------+            +----------------+ |
|            |                                 |        |
|            +------------+         +-----------+       |
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
