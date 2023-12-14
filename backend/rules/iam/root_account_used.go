package iam

import (
	"fmt"

	"github.com/Zeus-Labs/ZeusCloud/rules/types"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
)

type RootAccountUsed struct{}

func (RootAccountUsed) UID() string {
	return "iam/root_account_used"
}

func (RootAccountUsed) Description() string {
	return "Root Account should not be actively used"
}

func (RootAccountUsed) Severity() types.Severity {
	return types.Moderate
}

func (RootAccountUsed) RiskCategories() types.RiskCategoryList {
	return []types.RiskCategory{
		types.IamMisconfiguration,
		types.InsufficientMonitoring,
	}
}

func (RootAccountUsed) Execute(tx neo4j.Transaction) ([]types.Result, error) {
	records, err := tx.Run(
		`MATCH (a:AWSAccount{inscope: true})-[:RESOURCE]->(u:CredentialReportUser)
		WHERE u.user = '<root_account>'
		WITH a, u, datetime().epochSeconds as currentTime, 90 * 24 * 60 * 60 as ninetyDays
		RETURN u.arn as resource_id,
		'AWSUser' as resource_type,
		a.id as account_id,    
		CASE 
			WHEN u.password_last_used is NOT NULL AND currentTime - u.password_last_used <= ninetyDays THEN 'failed'
			WHEN u.access_key_1_last_used_date is NOT NULL AND currentTime - u.access_key_1_last_used_date <= ninetyDays THEN 'failed'
			WHEN u.access_key_2_last_used_date is NOT NULL AND currentTime - u.access_key_2_last_used_date <= ninetyDays THEN 'failed'
			ELSE 'passed'
		END as status,
		CASE 
			WHEN u.password_last_used is NOT NULL AND currentTime - u.password_last_used <= ninetyDays THEN 'Root account\'s password was used in the last 90 days.'
			WHEN u.access_key_1_last_used_date is NOT NULL AND currentTime - u.access_key_1_last_used_date <= ninetyDays THEN 'Root account\'s access key 1 was used in the last 90 days.'
			WHEN u.access_key_2_last_used_date is NOT NULL AND currentTime - u.access_key_2_last_used_date <= ninetyDays THEN 'Root account\'s access key 2 was used in the last 90 days.'
			ELSE 'Root account\'s password and access keys have not been used in the last 90 days.'
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

func (RootAccountUsed) ProduceRuleGraph(tx neo4j.Transaction, resourceId string) (neo4j.Result, error) {
	return nil, nil
}
