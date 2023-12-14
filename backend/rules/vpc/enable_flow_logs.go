package vpc

import (
	"fmt"

	"github.com/Zeus-Labs/ZeusCloud/rules/types"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
)

type EnableFlowLogs struct{}

func (EnableFlowLogs) UID() string {
	return "vpc/enable_flow_logs"
}

func (EnableFlowLogs) Description() string {
	return "Flow logs for VPC should be enabled and active."
}

func (EnableFlowLogs) Severity() types.Severity {
	return types.Moderate
}

func (EnableFlowLogs) RiskCategories() types.RiskCategoryList {
	return []types.RiskCategory{
		types.InsufficientMonitoring,
	}
}

func (EnableFlowLogs) Execute(tx neo4j.Transaction) ([]types.Result, error) {
	records, err := tx.Run(
		`MATCH (a:AWSAccount{inscope: true})-[:RESOURCE]->(v:AWSVpc)
		WHERE v.state = 'available'
		OPTIONAL MATCH (f:FlowLog)-[:MONITORS]->(v)
		WITH a, v, SUM(
			CASE WHEN f.flow_log_status = 'ACTIVE' THEN 1 ELSE 0 END
		) as num_flow_log_enabled
		RETURN v.id as resource_id,
		'AWSVpc' as resource_type,
		a.id as account_id, 
		CASE
			WHEN num_flow_log_enabled > 0 THEN 'passed'
			ELSE 'failed'
		END as status,
		CASE
			WHEN num_flow_log_enabled > 0 THEN 'Flow log is enabled and active for VPC.'
			ELSE 'Flow log is not enabled and active for VPC.'
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

func (EnableFlowLogs) ProduceRuleGraph(tx neo4j.Transaction, resourceId string) (neo4j.Result, error) {
	return nil, nil
}
