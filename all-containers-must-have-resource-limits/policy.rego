package env0

deny[msg] {
    r := input.plan.resource_changes[_]
    r.type == "kubernetes_deployment"
    
    container := r.change.after.spec.template.spec.container[_]
    not container.resources.limits
    
    msg := sprintf("Container '%s' must have resource limits defined.", [container.name])
}

deny[msg] {
    r := input.plan.resource_changes[_]
    r.type == "kubernetes_deployment"
    
    container := r.change.after.spec[_].template.spec.container[_]
    not container.resources.limits
    
    msg := sprintf("Container '%s' must have resource limits defined.", [container.name])
}

deny[msg] {
    r := input.plan.resource_changes[_]
    r.type == "kubernetes_deployment"
    
    container := r.change.after.spec.template.spec[_].container[_]
    not container.resources.limits
    
    msg := sprintf("Container '%s' must have resource limits defined.", [container.name])
}

deny[msg] {
    r := input.plan.resource_changes[_]
    r.type == "kubernetes_deployment"
    
    container := r.change.after.spec[_].template[_].spec.container[_]
    not container.resources.limits
    
    msg := sprintf("Container '%s' must have resource limits defined.", [container.name])
}
