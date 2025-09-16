package env0

import rego.v1

# Check containers in kubernetes_deployment resources
deny[msg] if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_deployment"
	container := r.change.after.spec.template.spec.container[_]
	not container.resources.limits
	msg := sprintf("Container '%s' must have resource limits defined.", [container.name])
}

deny[msg] if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_deployment"
	container := r.change.after.spec[_].template.spec.container[_]
	not container.resources.limits
	msg := sprintf("Container '%s' must have resource limits defined.", [container.name])
}

deny[msg] if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_deployment"
	container := r.change.after.spec.template.spec[_].container[_]
	not container.resources.limits
	msg := sprintf("Container '%s' must have resource limits defined.", [container.name])
}

deny[msg] if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_deployment"
	container := r.change.after.spec[_].template[_].spec.container[_]
	not container.resources.limits
	msg := sprintf("Container '%s' must have resource limits defined.", [container.name])
}

deny[msg] if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_deployment"
	container := r.change.after.spec[_].template[_].spec[_].container[_]
	not container.resources.limits
	msg := sprintf("Container '%s' must have resource limits defined.", [container.name])
}

# Check containers in kubernetes_manifest resources - template specs
deny[msg] if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_manifest"
	container := r.change.after.manifest.spec.template.spec.containers[_]
	not container.resources.limits
	msg := sprintf("Container '%s' must have resource limits defined.", [container.name])
}

deny[msg] if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_manifest"
	container := r.change.after.manifest.spec[_].template.spec.containers[_]
	not container.resources.limits
	msg := sprintf("Container '%s' must have resource limits defined.", [container.name])
}

deny[msg] if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_manifest"
	container := r.change.after.manifest.spec.template.spec[_].containers[_]
	not container.resources.limits
	msg := sprintf("Container '%s' must have resource limits defined.", [container.name])
}

deny[msg] if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_manifest"
	container := r.change.after.manifest.spec[_].template[_].spec.containers[_]
	not container.resources.limits
	msg := sprintf("Container '%s' must have resource limits defined.", [container.name])
}

deny[msg] if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_manifest"
	container := r.change.after.manifest.spec[_].template.spec[_].containers[_]
	not container.resources.limits
	msg := sprintf("Container '%s' must have resource limits defined.", [container.name])
}

deny[msg] if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_manifest"
	container := r.change.after.manifest.spec[_].template[_].spec[_].containers[_]
	not container.resources.limits
	msg := sprintf("Container '%s' must have resource limits defined.", [container.name])
}

# Check containers in kubernetes_manifest resources - direct specs (Pods)
deny[msg] if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_manifest"
	container := r.change.after.manifest.spec.containers[_]
	not container.resources.limits
	msg := sprintf("Container '%s' must have resource limits defined.", [container.name])
}

deny[msg] if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_manifest"
	container := r.change.after.manifest.spec[_].containers[_]
	not container.resources.limits
	msg := sprintf("Container '%s' must have resource limits defined.", [container.name])
}

# Check containers in kubernetes_manifest resources - CronJob jobTemplates
deny[msg] if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_manifest"
	container := r.change.after.manifest.spec.jobTemplate.spec.template.spec.containers[_]
	not container.resources.limits
	msg := sprintf("Container '%s' must have resource limits defined.", [container.name])
}

deny[msg] if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_manifest"
	container := r.change.after.manifest.spec[_].jobTemplate.spec.template.spec.containers[_]
	not container.resources.limits
	msg := sprintf("Container '%s' must have resource limits defined.", [container.name])
}

deny[msg] if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_manifest"
	container := r.change.after.manifest.spec.jobTemplate[_].spec.template.spec.containers[_]
	not container.resources.limits
	msg := sprintf("Container '%s' must have resource limits defined.", [container.name])
}

deny[msg] if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_manifest"
	container := r.change.after.manifest.spec.jobTemplate.spec[_].template.spec.containers[_]
	not container.resources.limits
	msg := sprintf("Container '%s' must have resource limits defined.", [container.name])
}

deny[msg] if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_manifest"
	container := r.change.after.manifest.spec.jobTemplate.spec.template[_].spec.containers[_]
	not container.resources.limits
	msg := sprintf("Container '%s' must have resource limits defined.", [container.name])
}

deny[msg] if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_manifest"
	container := r.change.after.manifest.spec.jobTemplate.spec.template.spec[_].containers[_]
	not container.resources.limits
	msg := sprintf("Container '%s' must have resource limits defined.", [container.name])
}
