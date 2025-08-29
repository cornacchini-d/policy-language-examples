# Esempi di Linguaggi di Policy

Questa cartella contiene il codice delle policy presente nel Capitolo 4: Analisi Pratica di Linguaggi di Policy, raggruppato per linguaggio. Ogni file riproduce il corrispondente listing.

- XACML (`xacml/`)
  - `policy.xml`: Listing code:xacml-example (insieme di policy per l’app documentale multi-tenant)
  - `request-employee-public.xml`: Listing code:xacml-req (richiesta employee/public/stesso tenant)
- OPA/Rego (`opa-rego/`)
  - `policy.rego`: Listing code:rego-example (modulo di policy)
  - `request.json`: Listing code:opa-example (input di valutazione)
- Cedar (`cedar/`)
  - `policy.cedar`: Listing code:cedar-example (regole di policy)
  - `schema.json`: Listing code:js-example (schema tipi)
  - `request.json`: Listing code:cedar-req (input di valutazione)