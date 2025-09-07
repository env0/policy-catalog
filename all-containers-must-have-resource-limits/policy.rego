package env0

deny[msg] {
    r := input.plan.resource_changes[_]
    r.type == "kubernetes_deployment"
    
    container := get_container(r.change.after)
    not container.resources.limits
    
    msg := sprintf("Container must have resource limits defined. Container: %v", [container.name])
}

get_container(deployment) := container {
    container := deployment.spec.template.spec.container[_]
}

get_container(deployment) := container {
    container := deployment.spec[_].template.spec.container[_]
}

get_container(deployment) := container {
    container := deployment.spec.template.spec[_].container[_]
}

get_container(deployment) := container {
    container := deployment.spec[_].template[_].spec.container[_]
}

get_container(deployment) := container {
    container := deployment.spec[_].template.spec[_].container[_]
}

get_container(deployment) := container {
    container := deployment.spec[_].template[_].spec[_].container[_]
}
