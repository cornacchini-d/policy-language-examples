package policy

# Accesso negato di default (negazione implicita)
default allow = false

# Accesso completo per utenti con ruolo admin se il documento appartiene al loro tenant
allow {
  input.action == "read"
  user := input.user
  doc := input.document

  user.role == "admin"
  user.tenant == doc.tenant
}

# Accesso per manager a documenti internal o public nel loro tenant
allow {
  input.action == "read"
  user := input.user
  doc := input.document

  user.role == "manager"
  user.tenant == doc.tenant
  doc.classification == "internal" or doc.classification == "public"
}

# Accesso per dipendenti a documenti public nel loro tenant
allow {
  input.action == "read"
  user := input.user
  doc := input.document

  user.role == "employee"
  user.tenant == doc.tenant
  doc.classification == "public"
}

# Accesso condiviso
allow {
  input.action == "read"
  user := input.user
  doc := input.document

  # shared_with deve essere una lista (es. array di tenant)
  doc.shared_with[_] == user.tenant
}
