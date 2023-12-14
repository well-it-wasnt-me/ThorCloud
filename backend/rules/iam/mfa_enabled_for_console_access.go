package iam

import (
	"fmt"

	"github.com/Zeus-Labs/ZeusCloud/rules/types"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
)

type MfaEnabledForConsoleAccess struct{}

func (MfaEnabledForConsoleAccess) UID() string {
	return "iam/mfa_enabled_for_console_access"
}

func (MfaEnabledForConsoleAccess) Description() string {
	return "MFA should be enabled for all IAM users with a console password."
}

func (MfaEnabledForConsoleAccess) Severity() types.Severity {
	return types.High
}

func (MfaEnabledForConsoleAccess) RiskCategories() types.RiskCategoryList {
	return []types.RiskCategory{
		types.IamMisconfiguration,
	}
}

func (MfaEnabledForConsoleAccess) Execute(tx neo4j.Transaction) ([]types.Result, error) {
	records, err := tx.Run(
		`MATCH (a:AWSAccount{inscope: true})-[:RESOURCE]->(u:CredentialReportUser)
		WHERE u.password_enabled
		RETURN u.arn as resource_id,
		'AWSUser' as resource_type,
		a.id as account_id, 
		CASE 
			WHEN u.mfa_active THEN 'passed'
			ELSE 'failed'
		END as status,
		CASE 
			WHEN u.mfa_active THEN 'The user has MFA enabled.'
			ELSE 'The user doesn\'t have MFA enabled.'
		END as context`,
		nil,
	)
	if err != nil {
		return nil, err
	}
	var results []types.Result
	for records.Next() {
		record := records.Record()
		resourceID, _ := record.Get("resource_id")
		resourceIDStr, ok := resourceID.(string)
		if !ok {
			return nil, fmt.Errorf("resource_id %v should be of type string", resourceID)
		}
		resourceType, _ := record.Get("resource_type")
		resourceTypeStr, ok := resourceType.(string)
		if !ok {
			return nil, fmt.Errorf("resource_type %v should be of type string", resourceType)
		}
		accountID, _ := record.Get("account_id")
		accountIDStr, ok := accountID.(string)
		if !ok {
			return nil, fmt.Errorf("account_id %v should be of type string", accountID)
		}
		status, _ := record.Get("status")
		statusStr, ok := status.(string)
		if !ok {
			return nil, fmt.Errorf("status %v should be of type string", status)
		}
		context, _ := record.Get("context")
		contextStr, ok := context.(string)
		if !ok {
			return nil, fmt.Errorf("context %v should be of type string", context)
		}
		results = append(results, types.Result{
			ResourceID:   resourceIDStr,
			ResourceType: resourceTypeStr,
			AccountID:    accountIDStr,
			Status:       statusStr,
			Context:      contextStr,
		})
	}
	return results, nil
}

func (MfaEnabledForConsoleAccess) ProduceRuleGraph(tx neo4j.Transaction, resourceId string) (neo4j.Result, error) {
	return nil, nil
}
