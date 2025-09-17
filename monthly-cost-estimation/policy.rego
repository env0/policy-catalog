package env0

# Threshold configured via input.policyData.maxCostIncrease
maxCostIncrease := input.policyData.maxCostIncrease
monthlyDiff     := input.costEstimation.monthlyCostDiff

# Deny if the cost increase is above the configured threshold.
deny[msg] {
  is_number(monthlyDiff)
  is_number(maxCostIncrease)
  monthlyDiff > maxCostIncrease
  msg := sprintf(
    "Monthly cost increase of $%.2f exceeds the threshold of $%.2f",
    [monthlyDiff, maxCostIncrease],
  )
}
