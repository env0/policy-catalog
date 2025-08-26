package env0

# Policy to request approval for cost increases above a threshold
# Default threshold is $5 if not configured

default maxCostIncrease = 5

maxCostIncrease = input.policyData.maxCostIncrease {
  input.policyData.maxCostIncrease
}

allow[msg] {
  input.costEstimation.monthlyCostDiff <= maxCostIncrease
  msg := sprintf("Monthly cost increase of $%.2f is within the acceptable threshold of $%.2f", [input.costEstimation.monthlyCostDiff, maxCostIncrease])
}

pending[msg] {
  input.costEstimation.monthlyCostDiff > maxCostIncrease
  msg := sprintf("Monthly cost increase of $%.2f exceeds the threshold of $%.2f - approval required", [input.costEstimation.monthlyCostDiff, maxCostIncrease])
}
