package env0

# Check containers in kubernetes_deployment resources
deny[msg]

if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_deployment"
	container := r.change.after.spec.template.spec.container[_]
	not image_allowed(container.image)
	msg := sprintf("Container '%s' uses unauthorized registry. Image: %s", [container.name, container.image])
}

deny[msg]

if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_deployment"
	container := r.change.after.spec[_].template.spec.container[_]
	not image_allowed(container.image)
	msg := sprintf("Container '%s' uses unauthorized registry. Image: %s", [container.name, container.image])
}

deny[msg]

if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_deployment"
	container := r.change.after.spec.template.spec[_].container[_]
	not image_allowed(container.image)
	msg := sprintf("Container '%s' uses unauthorized registry. Image: %s", [container.name, container.image])
}

deny[msg]

if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_deployment"
	container := r.change.after.spec[_].template[_].spec.container[_]
	not image_allowed(container.image)
	msg := sprintf("Container '%s' uses unauthorized registry. Image: %s", [container.name, container.image])
}

deny[msg]

if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_deployment"
	container := r.change.after.spec[_].template[_].spec[_].container[_]
	not image_allowed(container.image)
	msg := sprintf("Container '%s' uses unauthorized registry. Image: %s", [container.name, container.image])
}

# Check containers in kubernetes_manifest resources - template specs
deny[msg]

if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_manifest"
	container := r.change.after.manifest.spec.template.spec.containers[_]
	not image_allowed(container.image)
	msg := sprintf("Container '%s' uses unauthorized registry. Image: %s", [container.name, container.image])
}

deny[msg]

if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_manifest"
	container := r.change.after.manifest.spec[_].template.spec.containers[_]
	not image_allowed(container.image)
	msg := sprintf("Container '%s' uses unauthorized registry. Image: %s", [container.name, container.image])
}

deny[msg]

if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_manifest"
	container := r.change.after.manifest.spec.template.spec[_].containers[_]
	not image_allowed(container.image)
	msg := sprintf("Container '%s' uses unauthorized registry. Image: %s", [container.name, container.image])
}

deny[msg]

if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_manifest"
	container := r.change.after.manifest.spec[_].template[_].spec.containers[_]
	not image_allowed(container.image)
	msg := sprintf("Container '%s' uses unauthorized registry. Image: %s", [container.name, container.image])
}

deny[msg]

if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_manifest"
	container := r.change.after.manifest.spec[_].template.spec[_].containers[_]
	not image_allowed(container.image)
	msg := sprintf("Container '%s' uses unauthorized registry. Image: %s", [container.name, container.image])
}

deny[msg]

if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_manifest"
	container := r.change.after.manifest.spec[_].template[_].spec[_].containers[_]
	not image_allowed(container.image)
	msg := sprintf("Container '%s' uses unauthorized registry. Image: %s", [container.name, container.image])
}

# Check containers in kubernetes_manifest resources - direct specs (Pods)
deny[msg]

if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_manifest"
	container := r.change.after.manifest.spec.containers[_]
	not image_allowed(container.image)
	msg := sprintf("Container '%s' uses unauthorized registry. Image: %s", [container.name, container.image])
}

deny[msg]

if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_manifest"
	container := r.change.after.manifest.spec[_].containers[_]
	not image_allowed(container.image)
	msg := sprintf("Container '%s' uses unauthorized registry. Image: %s", [container.name, container.image])
}

# Check containers in kubernetes_manifest resources - CronJob jobTemplates
deny[msg]

if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_manifest"
	container := r.change.after.manifest.spec.jobTemplate.spec.template.spec.containers[_]
	not image_allowed(container.image)
	msg := sprintf("Container '%s' uses unauthorized registry. Image: %s", [container.name, container.image])
}

deny[msg]

if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_manifest"
	container := r.change.after.manifest.spec[_].jobTemplate.spec.template.spec.containers[_]
	not image_allowed(container.image)
	msg := sprintf("Container '%s' uses unauthorized registry. Image: %s", [container.name, container.image])
}

deny[msg]

if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_manifest"
	container := r.change.after.manifest.spec.jobTemplate[_].spec.template.spec.containers[_]
	not image_allowed(container.image)
	msg := sprintf("Container '%s' uses unauthorized registry. Image: %s", [container.name, container.image])
}

deny[msg]

if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_manifest"
	container := r.change.after.manifest.spec.jobTemplate.spec[_].template.spec.containers[_]
	not image_allowed(container.image)
	msg := sprintf("Container '%s' uses unauthorized registry. Image: %s", [container.name, container.image])
}

deny[msg]

if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_manifest"
	container := r.change.after.manifest.spec.jobTemplate.spec.template[_].spec.containers[_]
	not image_allowed(container.image)
	msg := sprintf("Container '%s' uses unauthorized registry. Image: %s", [container.name, container.image])
}

deny[msg]

if {
	r := input.plan.resource_changes[_]
	r.type == "kubernetes_manifest"
	container := r.change.after.manifest.spec.jobTemplate.spec.template.spec[_].containers[_]
	not image_allowed(container.image)
	msg := sprintf("Container '%s' uses unauthorized registry. Image: %s", [container.name, container.image])
}

# Helper function to check if image is from allowed registry
image_allowed(image) = true

if {
	registry := input.policyData.allowed_registries[_]
	startswith(image, registry)
}
