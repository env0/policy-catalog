package env0

import rego.v1

# Policy to request approval for cost increases above a threshold
# Threshold must be configured via policyData.maxCostIncrease

maxCostIncrease := input.policyData.maxCostIncrease

allow[msg] if {
	input.costEstimation.monthlyCostDiff <= maxCostIncrease
	msg := sprintf("Monthly cost increase of $%.2f is within the acceptable threshold of $%.2f", [input.costEstimation.monthlyCostDiff, maxCostIncrease])
}

allow[msg] if {
	input.costEstimation.monthlyCostDiff > maxCostIncrease
	count(input.approvers) >= 1
	msg := sprintf("Monthly cost increase of $%.2f approved by %d approver(s)", [input.costEstimation.monthlyCostDiff, count(input.approvers)])
}

pending[msg] if {
	input.costEstimation.monthlyCostDiff > maxCostIncrease
	count(input.approvers) == 0
	msg := sprintf("Monthly cost increase of $%.2f exceeds the threshold of $%.2f - approval required", [input.costEstimation.monthlyCostDiff, maxCostIncrease])
}
