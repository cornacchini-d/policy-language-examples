// Accesso completo per gli utenti con ruolo "admin"
// se il documento appartiene al loro stesso tenant
permit(principal, action == MyApp::Action::"read", resource)
when {
    principal.role == "admin"
    && principal.tenant == resource.tenant
};

// I manager possono leggere documenti classificati come
// internal o public se appartengano al proprio tenant
permit(principal, action == MyApp::Action::"read", resource)
when {
    principal.role == "manager"
    && principal.tenant == resource.tenant
    && (resource.classification == "internal" || resource.classification == "public")
};

// I dipendenti (employee) possono accedere solo ai documenti public
// appartenenti al proprio tenant
permit(principal, action == MyApp::Action::"read", resource)
when {
    principal.role == "employee"
    && principal.tenant == resource.tenant
    && resource.classification == "public"
};

// Accesso condiviso
permit(principal, action == MyApp::Action::"read", resource)
when {
    resource.shared_with.contains(principal.tenant)
};
