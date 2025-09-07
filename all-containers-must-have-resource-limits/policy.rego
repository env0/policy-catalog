package env0

deny[msg] {
    r := input.plan.resource_changes[_]
    r.type == "kubernetes_deployment"
    container := r.change.after.spec[_].template[_].spec[_].container[_]
    not container.resources.limits
    msg := "All containers must have resource limits defined."
}
