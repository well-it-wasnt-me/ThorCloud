package attackpath

import (
	"fmt"

	"github.com/Zeus-Labs/ZeusCloud/rules/types"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
)

type PubliclyExposedVmHighCVECritical struct{}

func (PubliclyExposedVmHighCVECritical) UID() string {
	return "attackpath/publicly_exposed_vm_high_permissions_critical_cve"
}

func (PubliclyExposedVmHighCVECritical) Description() string {
	return "Publicly exposed VM instance with critical CVE and high permissions."
}

func (PubliclyExposedVmHighCVECritical) Severity() types.Severity {
	return types.Critical
}

func (PubliclyExposedVmHighCVECritical) RiskCategories() types.RiskCategoryList {
	return []types.RiskCategory{
		types.PubliclyExposed,
		types.IamMisconfiguration,
		types.Vulnerability,
	}
}

// EC2 is considered publicly exposed if
// - it's directly exposed through security group / IP
// - it's exposed through an ELBv2
// TODO: Add other mechanisms of exposure like ELBv1?
func (PubliclyExposedVmHighCVECritical) Execute(tx neo4j.Transaction) ([]types.Result, error) {
	records, err := tx.Run(
		`MATCH (a:AWSAccount{inscope: true})-[:RESOURCE]->(e:EC2Instance)
		OPTIONAL MATCH
			(:IpRange{id: '0.0.0.0/0'})-[:MEMBER_OF_IP_RULE]->
			(:IpPermissionInbound)-[:MEMBER_OF_EC2_SECURITY_GROUP]->
			(instance_group:EC2SecurityGroup)<-[:MEMBER_OF_EC2_SECURITY_GROUP|NETWORK_INTERFACE*..2]-(e)-[:HAS_VULNERABILITY]->(ec2CVE:CVE {severity:"critical"})
		WITH a, e, collect(distinct instance_group.id) as instance_group_ids, collect(distinct COALESCE(ec2CVE.template_id, ec2CVE.vulnerabilityid)) as ec2_cve_ids
		OPTIONAL MATCH
			(:IpRange{range:'0.0.0.0/0'})-[:MEMBER_OF_IP_RULE]->
			(perm:IpPermissionInbound)-[:MEMBER_OF_EC2_SECURITY_GROUP]->
			(elbv2_group:EC2SecurityGroup)<-[:MEMBER_OF_EC2_SECURITY_GROUP]-
			(elbv2:LoadBalancerV2{scheme: 'internet-facing'})—[:ELBV2_LISTENER]->
			(listener:ELBV2Listener),
			(elbv2CVE:CVE {severity:"critical"})<-[HAS_VULNERABILITY]-(elbv2)-[:EXPOSE]->(e)
		WHERE listener.port >= perm.fromport AND listener.port <= perm.toport
		WITH a, e, instance_group_ids, ec2_cve_ids, collect(distinct elbv2.id) as public_elbv2_ids,collect(distinct elbv2CVE.template_id) as elbv2_cve_ids
		OPTIONAL MATCH
			(e)-[:STS_ASSUME_ROLE_ALLOW]->(role:AWSRole{is_high: True})
		WITH a, e, instance_group_ids, public_elbv2_ids, ec2_cve_ids, elbv2_cve_ids, collect(role.arn) as high_roles, collect(role.high_reason) as high_reasons
		WITH a, e, instance_group_ids, public_elbv2_ids, ec2_cve_ids, elbv2_cve_ids, high_roles, high_reasons,
		(e.publicipaddress IS NOT NULL AND size(instance_group_ids) > 0 AND size(ec2_cve_ids) > 0) OR (size(public_elbv2_ids) > 0 AND size(elbv2_cve_ids) > 0) as publicly_exposed_critical_cve_vm,
		(size(high_roles) > 0) as is_high
		RETURN e.id as resource_id,
		'EC2Instance' as resource_type,
		a.id as account_id,
		CASE 
			WHEN publicly_exposed_critical_cve_vm AND is_high THEN 'failed'
			ELSE 'passed'
		END as status,
		CASE 
			WHEN publicly_exposed_critical_cve_vm THEN (
				'The instance is publicly exposed. ' +
				CASE 
					WHEN e.publicipaddress IS NOT NULL THEN 'The instance has a public IP address: ' + e.publicipaddress + '.'
					ELSE 'The instance has no public IP address.'
				END + ' ' +
				CASE 
					WHEN size(instance_group_ids) > 0 THEN 'The following security groups attached to the instance allow traffic from 0.0.0.0/0: ' + substring(apoc.text.join(instance_group_ids, ', '), 0, 1000) + '.'
					ELSE 'No security group attached to the instance allows traffic from 0.0.0.0/0.'
				END + ' ' +
				CASE 
					WHEN size(public_elbv2_ids) > 0 THEN 'The instance is publicly exposed through these ELBv2 load balancers: ' + substring(apoc.text.join(public_elbv2_ids, ', '), 0, 1000) + '.'
					ELSE 'The instance is not publicly exposed through any ELBv2 load balancers.'
				END + '\n' +
				CASE
					WHEN size(ec2_cve_ids) > 0 THEN 'The following critical CVEs are detected for the EC2 Instance: ' + substring(apoc.text.join(ec2_cve_ids, ', '), 0, 1000) + '.'
					ELSE 'No critical CVEs are detected for the instance.'
				END + '' + 
				CASE 
					WHEN size(public_elbv2_ids) > 0 THEN 
						CASE
							WHEN size(elbv2_cve_ids) > 0 THEN 'The following critical CVEs are detected for the ELBv2 load balancers: ' + substring(apoc.text.join(elbv2_cve_ids, ', '), 0, 1000) + '.'
							ELSE 'No critical CVEs are detected for the ELBv2 load balancers.'
						END
					ELSE ''
				END 
			)
			ELSE 'The instance is neither directly publicly exposed, nor indirectly public exposed through an ELBv2 load balancer.'
		END + '\n' +
		CASE 
			WHEN is_high THEN (
				'The instance has high privileges in the account because of: ' + high_reasons[0] + '.'
			)
			ELSE 'The instance was not detected as being high-privileged in the account.'
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

func (PubliclyExposedVmHighCVECritical) ProduceRuleGraph(tx neo4j.Transaction, resourceId string) (neo4j.Result, error) {
	params := map[string]interface{}{
		"InstanceId": resourceId,
	}
	records, err := tx.Run(
		`MATCH (a:AWSAccount{inscope: true})-[:RESOURCE]->(e:EC2Instance{id: $InstanceId})
		OPTIONAL MATCH
			directPublicNucleiCvePath=
			(:IpRange{id: '0.0.0.0/0'})-[:MEMBER_OF_IP_RULE]->
			(:IpPermissionInbound)-[:MEMBER_OF_EC2_SECURITY_GROUP]->
			(instance_group:EC2SecurityGroup)<-[:MEMBER_OF_EC2_SECURITY_GROUP|NETWORK_INTERFACE*..2]-(e)-[:HAS_VULNERABILITY]->(nucleiCve:CVE:NUCLEI {severity:"critical"})
		WITH e, collect(directPublicNucleiCvePath) as directPublicNucleiCvePaths, collect(nucleiCve.template_id) as template_ids
		OPTIONAL MATCH 
		ec2InspectorCvePath=
		(e)-[:HAS_VULNERABILITY]->(inspectorCve:CVE:AWSInspectorFinding {severity:"critical"})
		WHERE NOT inspectorCve.vulnerabilityid IN template_ids
		WITH e, directPublicNucleiCvePaths, collect(ec2InspectorCvePath) as ec2InspectorCvePaths
		OPTIONAL MATCH
			(:IpRange{range:'0.0.0.0/0'})-[:MEMBER_OF_IP_RULE]->
			(perm:IpPermissionInbound)-[:MEMBER_OF_EC2_SECURITY_GROUP]->
			(elbv2_group:EC2SecurityGroup)<-[:MEMBER_OF_EC2_SECURITY_GROUP]-
			(elbv2:LoadBalancerV2{scheme: 'internet-facing'})—[:ELBV2_LISTENER]->
			(listener:ELBV2Listener),
			(e)<-[:EXPOSE]-(elbv2)-[:HAS_VULNERABILITY]->(:CVE {severity:"critical"})
		WHERE listener.port >= perm.fromport AND listener.port <= perm.toport
		OPTIONAL MATCH
			indirectPath=(iprange)-[:MEMBER_OF_IP_RULE]->(perm)-[:MEMBER_OF_EC2_SECURITY_GROUP]->
			(elbv2_group)<-[:MEMBER_OF_EC2_SECURITY_GROUP]-(elbv2)-[:EXPOSE]->(e)
		OPTIONAL MATCH 
			elbv2CvePath = (elbv2)-[HAS_VULNERABILITY]->(:CVE {severity:"critical"})
		WITH e, directPublicNucleiCvePaths, ec2InspectorCvePaths, collect(indirectPath) as indirectPaths,collect(elbv2CvePath) as elbv2CvePaths
		OPTIONAL MATCH
			highRolePath=
			(e)-[:STS_ASSUME_ROLE_ALLOW]->(role:AWSRole{is_high: True})
		WITH e, directPublicNucleiCvePaths, ec2InspectorCvePaths, indirectPaths,elbv2CvePaths,
		collect(highRolePath) as highRolePaths
		WITH directPublicNucleiCvePaths + ec2InspectorCvePaths + indirectPaths + elbv2CvePaths + highRolePaths AS paths
		RETURN paths`,
		params)
	if err != nil {
		return nil, err
	}

	return records, nil
}
