package env0

# Deny ALB listeners that use outdated TLS security policies
deny[msg] {
    # Skip policy validation for destroy operations
    input.deploymentRequest.type != "destroy"
    
    rc := input.plan.resource_changes[_]
    rc.type == "aws_lb_listener"
    
    # Only check listeners that will exist after the change (not being deleted)
    not is_delete_action(rc.change.actions)
    rc.change.after
    
    # Check if the listener has HTTPS protocol (TLS/SSL)
    rc.change.after.protocol == "HTTPS"
    
    # Get the minimum required TLS policy from configuration
    min_tls_policy := input.policyData.min_tls_policy
    
    # Check if ssl_policy is not set or doesn't match the minimum requirement
    not rc.change.after.ssl_policy
    
    msg := sprintf("%s: ALB listener must specify a TLS security policy", [rc.address])
}

# Deny ALB listeners with TLS policy that doesn't meet minimum requirements
deny[msg] {
    # Skip policy validation for destroy operations
    input.deploymentRequest.type != "destroy"
    
    rc := input.plan.resource_changes[_]
    rc.type == "aws_lb_listener"
    
    # Only check listeners that will exist after the change (not being deleted)
    not is_delete_action(rc.change.actions)
    rc.change.after
    
    # Check if the listener has HTTPS protocol (TLS/SSL)
    rc.change.after.protocol == "HTTPS"
    
    # Get the minimum required TLS policy from configuration
    min_tls_policy := input.policyData.min_tls_policy
    
    # Check if ssl_policy is set but doesn't match the minimum requirement
    rc.change.after.ssl_policy
    rc.change.after.ssl_policy != min_tls_policy
    not is_acceptable_tls_policy(rc.change.after.ssl_policy, min_tls_policy)
    
    msg := sprintf("%s: ALB listener is using TLS security policy '%s', but minimum required is '%s'", [rc.address, rc.change.after.ssl_policy, min_tls_policy])
}

# Helper function to check if actions include delete
is_delete_action(actions) {
    actions[_] == "delete"
}

# Helper function to determine if a TLS policy meets minimum requirements
# This is a simplified version - in practice, you might want more sophisticated policy comparison
is_acceptable_tls_policy(current_policy, min_policy) {
    # List of acceptable TLS policies in order of security (most secure first)
    acceptable_policies := [
        "ELBSecurityPolicy-TLS13-1-2-2021-06",
        "ELBSecurityPolicy-TLS-1-2-2017-01",
        "ELBSecurityPolicy-TLS-1-2-Ext-2018-06",
        "ELBSecurityPolicy-FS-2018-06"
    ]
    
    # Find the index of current and minimum policies
    current_index := policy_index(current_policy, acceptable_policies)
    min_index := policy_index(min_policy, acceptable_policies)
    
    # Current policy is acceptable if its index is less than or equal to minimum (more secure)
    current_index <= min_index
}

# Helper function to find policy index in acceptable policies list
policy_index(policy, policies) = index {
    policies[index] == policy
} else = 999 {
    # Return high index for unknown policies (treated as less secure)
    true
}