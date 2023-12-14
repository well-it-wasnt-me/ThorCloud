package inventory

import (
	"log"
	"time"

	"github.com/Zeus-Labs/ZeusCloud/util"
	"github.com/hashicorp/go-multierror"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
)

type LambdaFunction struct {
	Arn          *string    `json:"arn"`
	AccountId    *string    `json:"account_id"`
	Name         *string    `json:"name"`
	ModifiedDate *time.Time `json:"modified_date"`
	State        *string    `json:"state"`
	Runtime      *string    `json:"runtime"`
	IamRoles     []string   `json:"iam_roles"`
}

func RetrieveLambdaFunctions(tx neo4j.Transaction) ([]interface{}, error) {
	records, err := tx.Run(
		`MATCH (a:AWSAccount{inscope: true})-[:RESOURCE]->(l:AWSLambda)
		OPTIONAL MATCH (l)-[:STS_ASSUME_ROLE_ALLOW]->(r:AWSRole)
		WITH a, l, collect(r.arn) as role_arns
		RETURN l.id as arn,
		a.id as account_id,
		l.name as name,
		l.modifieddate as modified_date,
		l.state as state,
		l.runtime as runtime,
		role_arns as iam_roles`,
		nil,
	)
	if err != nil {
		return nil, err
	}
	var retrievedLambdaFunctions []interface{}
	for records.Next() {
		record := records.Record()

		var parsingErrs error
		arnStr, err := util.ParseAsOptionalString(record, "arn")
		multierror.Append(parsingErrs, err)
		accountIDStr, err := util.ParseAsOptionalString(record, "account_id")
		multierror.Append(parsingErrs, err)
		nameStr, err := util.ParseAsOptionalString(record, "name")
		multierror.Append(parsingErrs, err)
		modifiedDate, err := util.ParseAsOptionalTimeISO8601(record, "modifieddate")
		multierror.Append(parsingErrs, err)
		stateStr, err := util.ParseAsOptionalString(record, "state")
		multierror.Append(parsingErrs, err)
		runtimeStr, err := util.ParseAsOptionalString(record, "runtime")
		multierror.Append(parsingErrs, err)
		iamRolesLst, err := util.ParseAsOptionalStringList(record, "iam_roles")
		multierror.Append(parsingErrs, err)
		if parsingErrs != nil {
			log.Printf("Encountered errors parsing resource: %v, continuing on...", parsingErrs.Error())
		}

		retrievedLambdaFunctions = append(retrievedLambdaFunctions, LambdaFunction{
			Arn:          arnStr,
			AccountId:    accountIDStr,
			Name:         nameStr,
			ModifiedDate: modifiedDate,
			State:        stateStr,
			Runtime:      runtimeStr,
			IamRoles:     iamRolesLst,
		})
	}

	return retrievedLambdaFunctions, nil
}
