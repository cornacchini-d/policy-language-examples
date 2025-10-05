package policy

import rego.v1

# Accesso negato di default (negazione implicita)
default allow := false

# Accesso completo per utenti con ruolo admin se il documento appartiene al loro tenant
allow if {
	input.action == "read"
	input.user.role == "admin"
	input.user.tenant == input.document.tenant
}

# Accesso per manager a documenti internal o public nel loro tenant
allow if {
	input.action == "read"
	input.user.role == "manager"
	input.user.tenant == input.document.tenant
	input.document.classification in {"internal", "public"}
}

# Accesso per dipendenti a documenti public nel loro tenant
allow if {
	input.action == "read"
	input.user.role == "employee"
	input.user.tenant == input.document.tenant
	input.document.classification == "public"
}

# Accesso condiviso
allow if {
	input.action == "read"
	some tenant in input.document.shared_with
	tenant == input.user.tenant
}
