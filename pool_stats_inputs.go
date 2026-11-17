package main

import "time"

type accountBillingInput struct {
	accountID   string
	accountType AccountType
	plan        string
	addedAt     time.Time
}

func billingPlan(planType, tier string) string {
	switch tier {
	case "default_claude_max_20x":
		return "max_20x"
	case "default_claude_max_5x":
		return "max_5x"
	default:
		return accountPlanForSubscription(planType)
	}
}
