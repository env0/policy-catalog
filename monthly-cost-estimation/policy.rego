package env0.policies.monthly_cost_estimation

# Policy to request approval for cost increases above a threshold
# Default threshold is $10 if not configured

default maxCostIncrease = 10

maxCostIncrease = input.policyData.maxCostIncrease {
  input.policyData.maxCostIncrease
}

pending[msg] {
  input.costEstimation.monthlyCostDiff > maxCostIncrease
  msg := sprintf("Monthly cost increase of $%.2f exceeds the threshold of $%.2f - approval required", [input.costEstimation.monthlyCostDiff, maxCostIncrease])
}
