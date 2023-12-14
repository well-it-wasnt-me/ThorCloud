from cartography.intel.aws import permission_relationships


GET_OBJECT_LOWERCASE_RESOURCE_WILDCARD = [
    {
        "action": [
            "s3:Get*",
        ],

        "resource": [
            "arn:aws:s3:::test*",
        ],
        "effect": "Allow",
    },
]


def test_admin_statements():
    statement = [{
        "action": [
            "*",
        ],

        "resource": [
            "*",
        ],
        "effect": "Allow",
    }]
    assert (True, False) == permission_relationships.evaluate_policy_for_permission(
        statement, "arn:aws:s3:::testbucket", "S3:GetObject",
    )


def test_calculate_seed_high_principals():
    iam_principals = {
        "arn:aws:iam::000000000000:role/non_admin_role_1": {
            "ListAllow": [{
                "action": [
                    "s3:*",
                ],
                "resource": [
                    "*",
                ],
                "effect": "Allow",
            }],
            "explicitallow": [{
                "action": [
                    "s3:getobject",
                ],
                "resource": [
                    "arn:aws:s3:::testbucket",
                ],
                "effect": "Allow",
            }],
        },
        "arn:aws:iam::000000000000:role/non_admin_role_2": {
            "ListAllow": [{
                "action": [
                    "*",
                ],
                "resource": [
                    "*",
                ],
                "effect": "Allow",
            }],
        },
        "arn:aws:iam::000000000000:role/non_admin_role_3": {
            "ListAllow": [{
                "action": [
                    "ec2:*",
                ],
                "resource": [
                    "*",
                ],
                "effect": "Allow",
            }],
        },
        "arn:aws:iam::000000000000:role/non_admin_role_4": {
            "ListAllow": [{
                "action": [
                    "ec2:*",
                ],
                "resource": [
                    "arn:aws:ec2:us-east-1:000000000000:instance/instance-134fasf",
                ],
                "effect": "Allow",
            }],
        },
        "arn:aws:iam::000000000000:role/non_admin_role_5": {
            "ListAllow": [{
                "action": [
                    "ec2:*",
                ],
                "resource": [
                    "arn:aws:ec2:us-east-1:000000000000:instance/instance-134fasf",
                ],
                "effect": "Deny",
            }],
        },
        "arn:aws:iam::000000000000:role/high_role_6": {
            "ListAllow": [{
                "action": [
                    "ec2:*",
                ],
                "notaction":[
                    "ec2:AllocateAddress",
                ],
                "resource": [
                    "*",
                ],
                "effect": "Allow",
            }],
        },
        "arn:aws:iam::000000000000:role/non_high_role_7": {
            "ListAllow": [
                {
                    "action": [
                        "ec2:*",
                    ],
                    "resource": [
                        "*",
                    ],
                    "effect": "Allow",
                }, {
                    "action": [
                        "ec2:*",
                    ],
                    "resource": [
                        "*",
                    ],
                    "effect": "Deny",
                },
            ],
        },
        "arn:aws:iam::000000000000:user/high_user_7": {
            "ListAllow": [{
                "action": [
                    "ecr:*",
                ],
                "resource": [
                    "*",
                ],
                "effect": "Allow",
            }],
        },
        "arn:aws:iam::000000000000:user/non_high_user_8": {
            "ListAllow": [{
                "action": [
                    "ecr:*",
                    "ec2:*",
                ],
                "resource": [
                    "*",
                ],
                "effect": "Deny",
            }],
        },
        "arn:aws:iam::000000000000:user/high_user_9": {
            "ListDeny": [{
                "action": [
                    "ecr:*",
                    "ec2:*",
                ],
                "resource": [
                    "*",
                ],
                "effect": "Deny",
            }],
            "ListAllow": [{
                "action": [
                    "s3:*",
                ],
                "resource": [
                    "*",
                ],
                "effect": "Allow",
            }],
        },
        "arn:aws:iam::000012300000:user/not_high_user_10": {
            "ListDeny": [{
                "action": [
                    "ecr:*",
                    "ec2:*",
                ],
                "resource": [
                    "*",
                ],
                "effect": "Deny",
            }],
            "ListAllow": [{
                "action": [
                    "ecs:*",
                ],
                "resource": [
                    "arn:aws:ecs:us-east-1:000000000000:instance/instance-134fasf",
                ],
                "effect": "Allow",
            }],
        },
    }

    assert 6 == len(
        permission_relationships.calculate_seed_high_principals(
            iam_principals,
        ),
    )


def test_calculate_seed_admin_principals():
    iam_principals = {
        "arn:aws:iam::000000000000:role/non_admin_role_1": {
            "ListAllow": [{
                "action": [
                    "s3:listobject"
                    "dynamodb:query",
                ],
                "resource": [
                    "*",
                ],
                "effect": "Allow",
            }],
            "explicitallow": [{
                "action": [
                    "s3:getobject",
                ],
                "resource": [
                    "arn:aws:s3:::testbucket",
                ],
                "effect": "Allow",
            }],
        },
        "arn:aws:iam::000000000000:role/admin_role_2": {
            "Test": [
                {
                    "action": [
                        "iam:PutRolePolicy",
                    ],
                    "effect": "Allow",
                    "resource": ["*"],
                },
            ],
        },
        "arn:aws:iam::000000000000:role/admin_role_3": {
            "Test": [
                {
                    "action": [
                        "iam:PutRolePolicy",
                    ],
                    "effect": "Allow",
                    "resource": [
                        "arn:aws:iam::000000000000:role/admin_role_3",
                        "arn:aws:iam::000000000000:role/non_admin_role_4",
                    ],
                },
            ],
        },
        "arn:aws:iam::000000000000:role/admin_role_5": {
            "Test": [
                {
                    "action": [
                        "iam:AttachRolePolicy",
                    ],
                    "effect": "Allow",
                    "resource": ["*"],
                },
            ],
        },
        "arn:aws:iam::000000000000:user/admin_user_1": {
            "TestAllow": [{
                "action": [
                    "*",
                ],
                "effect": "Allow",
                "resource": ["*"],
            }],
        },
        "arn:aws:iam::000000000000:user/non_admin_user_2": {
            "TestDenyAllow": [
                {
                    "action": [
                        "*",
                    ],
                    "effect": "Deny",
                    "resource": ["*"],
                },
                {
                    "action": [
                        "*",
                    ],
                    "effect": "Allow",
                    "resource": ["*"],
                },
            ],
        },
        "arn:aws:iam::000000000000:user/admin_user_3": {
            "Test": [
                {
                    "action": [
                        "iam:PutUserPolicy",
                        "iam:RemoveUserFromGroup",
                    ],
                    "effect": "Allow",
                    "resource": ["*"],
                },
            ],
            "s3Allow": [{
                "action": [
                    "s3:getobject",
                ],
                "resource": [
                    "arn:aws:s3:::testbucket",
                ],
                "effect": "Allow",
            }],
        },
        "arn:aws:iam::000000000000:user/admin_user_4": {
            "Test": [
                {
                    "action": [
                        "iam:PutUserPolicy",
                    ],
                    "effect": "Allow",
                    "resource": ["arn:aws:iam::000000000000:user/admin_user_4"],
                },
            ],
        },
        "arn:aws:iam::000000000000:user/non_admin_user_5": {
            "Test": [
                {
                    "action": [
                        "iam:PutUserPolicy",
                    ],
                    "effect": "Allow",
                    "resource": ["arn:aws:iam::000000000000:user/random_user_6"],
                },
            ],
        },
        "arn:aws:iam::000000000011:group/admin_group_1": {
            "TestGroup": [
                {
                    "action": [
                        "iam:AttachGroupPolicy",
                    ],
                    "effect": "Allow",
                    "resource": ["arn:aws:iam::000000000011:group/admin_group_1"],
                },
            ],
        },
        "arn:aws:iam::000000000011:group/non_admin_group_2": {
            "TestGroup": [
                {
                    "action": [
                        "iam:AttachGroupPolicy",
                    ],
                    "effect": "Deny",
                    "resource": ["arn:aws:iam::000000000011:group/non_admin_group_2"],
                },
            ],
        },
    }
    assert 7 == len(
        permission_relationships.calculate_seed_admin_principals(
            iam_principals,
        ),
    )


def test_not_action_statement():
    statement = [{
        "action": [
            "*",
        ],
        "notaction":[
            "S3:GetObject",
        ],
        "resource": [
            "*",
        ],
        "effect": "Allow",
    }]
    assert (False, False) == permission_relationships.evaluate_policy_for_permission(
        statement, "arn:aws:s3:::testbucket", "S3:GetObject",
    )


def test_deny_statement():
    statement = [
        {
            "action": [
                "*",
            ],

            "resource": [
                "*",
            ],
            "effect": "Allow",
        },
        {
            "action": [
                "S3:GetObject",
            ],

            "resource": [
                "*",
            ],
            "effect": "Deny",
        },
    ]
    assert (False, True) == permission_relationships.evaluate_policy_for_permission(
        statement, "arn:aws:s3:::testbucket", "S3:GetObject",
    )


def test_single_permission():
    statement = [
        {
            "action": [
                "S3:GetObject",
            ],

            "resource": [
                "*",
            ],
            "effect": "Allow",
        },
    ]
    assert (True, False) == permission_relationships.evaluate_policy_for_permission(
        statement, "arn:aws:s3:::testbucket", "S3:GetObject",
    )


def test_single_non_matching_permission():
    statement = [
        {
            "action": [
                "S3:GetObject",
            ],

            "resource": [
                "*",
            ],
            "effect": "Allow",
        },
    ]
    assert (False, False) == permission_relationships.evaluate_policy_for_permission(
        statement, "arn:aws:s3:::testbucket", "S3:PutObject",
    )


def test_single_permission_wildcard_resource():
    statement = [
        {
            "action": [
                "S3:GetObject",
            ],

            "resource": [
                "*",
            ],
            "effect": "Allow",
        },
    ]
    assert (True, False) == permission_relationships.evaluate_policy_for_permission(
        statement, "*", "S3:GetObject",
    )


def test_single_permission_lower_case():
    statement = [
        {
            "action": [
                "s3:Get*",
            ],

            "resource": [
                "*",
            ],
            "effect": "Allow",
        },
    ]
    assert (True, False) == permission_relationships.evaluate_policy_for_permission(
        statement, "arn:aws:s3:::testbucket", "S3:GetObject",
    )


def test_single_permission_resource_allow():
    statement = [
        {
            "action": [
                "s3:Get*",
            ],

            "resource": [
                "arn:aws:s3:::test*",
            ],
            "effect": "Allow",
        },
    ]
    assert (True, False) == permission_relationships.evaluate_policy_for_permission(
        statement, "arn:aws:s3:::testbucket", "S3:GetObject",
    )


def test_single_permission_resource_non_match():
    statement = [
        {
            "action": [
                "s3:Get*",
            ],

            "resource": [
                "arn:aws:s3:::nottest",
            ],
            "effect": "Allow",
        },
    ]
    assert (False, False) == permission_relationships.evaluate_policy_for_permission(
        statement, "arn:aws:s3:::testbucket", "S3:GetObject",
    )


def test_non_matching_notresource():
    statements = [
        {
            "action": [
                "s3:Get*",
            ],
            "resource":["*"],
            "notresource": [
                "arn:aws:s3:::nottest",
            ],
            "effect": "Allow",
        },
    ]
    assert (True, False) == permission_relationships.evaluate_policy_for_permission(
        statements, "arn:aws:s3:::testbucket", "S3:GetObject",
    )


def test_no_action_statement():
    statements = [{
        "notaction": [
            "dynamodb:Query",
        ],
        "resource": [
            "*",
        ],
        "effect": "Allow",
    }]
    assert (True, False) == permission_relationships.evaluate_policy_for_permission(
        statements, "arn:aws:s3:::testbucket", "S3:GetObject",
    )


def test_notaction_deny_without_allow():
    statements = [{
        "notaction": [
            "s3:*",
        ],
        "resource": [
            "*",
        ],
        "effect": "Allow",
    }]
    assert (False, False) == permission_relationships.evaluate_policy_for_permission(
        statements, "arn:aws:s3:::testbucket", "S3:GetObject",
    )


def test_notaction_malformed():
    statements = [{
        "notaction": [
            "s3.*",
        ],
        "resource": [
            "*",
        ],
        "effect": "Allow",
    }]
    assert (True, False) == permission_relationships.evaluate_policy_for_permission(
        statements, "arn:aws:s3:::testbucket", "S3:GetObject",
    )


def test_resource_substring():
    statements = [{
        "action": [
            "s3.*",
        ],
        "resource": [
            "arn:aws:s3:::test",
        ],
        "effect": "Allow",
    }]
    assert (False, False) == permission_relationships.evaluate_policy_for_permission(
        statements, "arn:aws:s3:::testbucket", "S3:GetObject",
    )


def test_full_policy_explicit_deny():
    policies = {
        "fakeallow": [{
            "action": [
                "s3:*",
            ],
            "resource": [
                "*",
            ],
            "effect": "Allow",
        }],
        "fakedeny": [{
            "action": [
                "s3:*",
            ],
            "resource": [
                "arn:aws:s3:::testbucket",
            ],
            "effect": "Deny",
        }],
    }
    assert not permission_relationships.principal_allowed_on_resource(
        policies, "arn:aws:s3:::testbucket", [{"permission": "S3:GetObject"}],
    )


def test_full_policy_no_explicit_allow():
    policies = {
        "ListAllow": [{
            "action": [
                "s3:List*",
            ],
            "resource": [
                "*",
            ],
            "effect": "Allow",
        }],
        "PutAllow": [{
            "action": [
                "s3:Put*",
            ],
            "resource": [
                "arn:aws:s3:::testbucket",
            ],
            "effect": "Allow",
        }],
    }
    assert not permission_relationships.principal_allowed_on_resource(
        policies, "arn:aws:s3:::testbucket", [{"permission": "S3:GetObject"}],
    )


def test_full_policy_explicit_allow():
    policies = {
        "ListAllow": [{
            "action": [
                "s3:listobject",
                "dynamodb:query",
            ],
            "resource": [
                "*",
            ],
            "effect": "Allow",
        }],
        "explicitallow": [{
            "action": [
                "s3:getobject",
            ],
            "resource": [
                "arn:aws:s3:::testbucket",
            ],
            "effect": "Allow",
        }],
    }
    assert permission_relationships.principal_allowed_on_resource(
        policies, "arn:aws:s3:::testbucket", [{"permission": "S3:GetObject"}],
    )


def test_full_policy_multiple_policy_specs():
    policies = {
        "ListAllow": [{
            "action": [
                "s3:listobject",
                "dynamodb:query",
            ],
            "resource": [
                "*",
            ],
            "effect": "Allow",
        }],
        "explicitallow": [{
            "action": [
                "s3:getobject",
            ],
            "resource": [
                "arn:aws:s3:::testbucket",
            ],
            "effect": "Allow",
        }],
    }
    assert permission_relationships.principal_allowed_on_resource(
        policies,
        "arn:aws:s3:::testbucket",
        [{"permission": "S3:GetObject"}, {"permission": "S3:ListObject"}],
        "AND",
    )


def test_full_policy_multiple_policy_specs_failing():
    policies = {
        "ListAllow": [{
            "action": [
                "s3:listobject",
                "dynamodb:query",
            ],
            "resource": [
                "*",
            ],
            "effect": "Allow",
        }],
        "explicitallow": [{
            "action": [
                "s3:getobject",
            ],
            "resource": [
                "arn:aws:s3:::testbucket",
            ],
            "effect": "Allow",
        }],
    }
    assert not permission_relationships.principal_allowed_on_resource(
        policies, "arn:aws:s3:::testbucket", [{"permission": "S3:GetObject"}, {"permission": "S3:PutObject"}], "AND",
    )


def test_full_policy_multiple_policy_specs_resource_override():
    policies = {
        "ListAllow": [{
            "action": [
                "s3:listobject",
                "dynamodb:query",
            ],
            "resource": [
                "*",
            ],
            "effect": "Allow",
        }],
        "explicitallow": [{
            "action": [
                "s3:getobject",
            ],
            "resource": [
                "arn:aws:s3:::testbucket",
            ],
            "effect": "Allow",
        }],
    }
    assert permission_relationships.principal_allowed_on_resource(
        policies,
        "arn:aws:s3:::testbucket",
        [{"permission": "S3:GetObject"}, {"permission": "S3:ListObject", "resource": "*"}],
        "AND",
    )


def test_full_policy_multiple_policy_specs_resource_override_failing():
    policies = {
        "ListAllow": [{
            "action": [
                "s3:listobject",
                "dynamodb:query",
            ],
            "resource": [
                "*",
            ],
            "effect": "Allow",
        }],
        "explicitallow": [{
            "action": [
                "s3:getobject",
            ],
            "resource": [
                "arn:aws:s3:::testbucket",
            ],
            "effect": "Allow",
        }],
    }
    assert not permission_relationships.principal_allowed_on_resource(
        policies,
        "arn:aws:s3:::testbucket",
        [{"permission": "S3:GetObject"}, {"permission": "S3:PutObject", "resource": "*"}],
        "AND",
    )


def test_full_multiple_principal():
    principals = {
        "test_principals1": {
            "ListAllow": [{
                "action": [
                    "s3:listobject",
                    "dynamodb:query",
                ],
                "resource": [
                    "*",
                ],
                "effect": "Allow",
            }],
            "explicitallow": [{
                "action": [
                    "s3:getobject",
                ],
                "resource": [
                    "arn:aws:s3:::testbucket",
                ],
                "effect": "Allow",
            }],
        },
        "test_principal2": {
            "ListAllow": [{
                "action": [
                    "s3:List*",
                ],
                "resource": [
                    "*",
                ],
                "effect": "Allow",
            }],
            "PutAllow": [{
                "action": [
                    "s3:Put*",
                ],
                "resource": [
                    "arn:aws:s3:::testbucket",
                ],
                "effect": "Allow",
            }],
        },
    }
    assert 2 == len(
        permission_relationships.calculate_permission_relationships(
            principals,
            ["arn:aws:s3:::testbucket"],
            [{"permission": "S3:GetObject"}],
            {"arn:aws:s3:::testbucket": True},
            "OR",
            {},
            False,
        ),
    )


def test_full_multiple_principal_multiple_policy_specs():
    principals = {
        "test_principals1": {
            "ListAllow": [{
                "action": [
                    "s3:listobject",
                    "dynamodb:query",
                ],
                "resource": [
                    "*",
                ],
                "effect": "Allow",
            }],
            "explicitallow": [{
                "action": [
                    "s3:getobject",
                ],
                "resource": [
                    "arn:aws:s3:::testbucket",
                ],
                "effect": "Allow",
            }],
        },
        "test_principal2": {
            "ListAllow": [{
                "action": [
                    "s3:List*",
                ],
                "resource": [
                    "*",
                ],
                "effect": "Allow",
            }],
            "PutAllow": [{
                "action": [
                    "s3:Put*",
                ],
                "resource": [
                    "arn:aws:s3:::testbucket",
                ],
                "effect": "Allow",
            }],
        },
    }
    assert 1 == len(
        permission_relationships.calculate_permission_relationships(
            principals, ["arn:aws:s3:::testbucket"],
            [{"permission": "S3:GetObject"}, {"permission": "S3:ListObject"}],
            {"arn:aws:s3:::testbucket": True},
            "AND",
            {},
            False,
        ),
    )


def test_full_multiple_principal_resource_spec_disallow():
    principals = {
        "test_principals1": {
            "ListAllow": [{
                "action": [
                    "s3:listobject",
                    "dynamodb:query",
                ],
                "resource": [
                    "*",
                ],
                "effect": "Allow",
            }],
            "explicitallow": [{
                "action": [
                    "s3:getobject",
                ],
                "resource": [
                    "arn:aws:s3:::testbucket",
                ],
                "effect": "Allow",
            }],
        },
        "test_principal2": {
            "ListAllow": [{
                "action": [
                    "s3:List*",
                ],
                "resource": [
                    "*",
                ],
                "effect": "Allow",
            }],
            "PutAllow": [{
                "action": [
                    "s3:Put*",
                ],
                "resource": [
                    "arn:aws:s3:::testbucket",
                ],
                "effect": "Allow",
            }],
        },
    }
    assert 0 == len(
        permission_relationships.calculate_permission_relationships(
            principals, ["arn:aws:s3:::testbucket"],
            [{"permission": "S3:GetObject"}, {"permission": "S3:ListObject"}],
            {"arn:aws:s3:::testbucket": False},
            "AND",
            {},
            False,
        ),
    )


def test_full_multiple_principal_resource_spec_none():
    principals = {
        "test_principals1": {
            "ListAllow": [{
                "action": [
                    "s3:listobject",
                    "dynamodb:query",
                ],
                "resource": [
                    "*",
                ],
                "effect": "Allow",
            }],
            "explicitallow": [{
                "action": [
                    "s3:getobject",
                ],
                "resource": [
                    "arn:aws:s3:::testbucket",
                ],
                "effect": "Allow",
            }],
        },
        "test_principal2": {
            "ListAllow": [{
                "action": [
                    "s3:List*",
                ],
                "resource": [
                    "*",
                ],
                "effect": "Allow",
            }],
            "PutAllow": [{
                "action": [
                    "s3:Put*",
                ],
                "resource": [
                    "arn:aws:s3:::testbucket",
                ],
                "effect": "Allow",
            }],
        },
    }
    assert 1 == len(
        permission_relationships.calculate_permission_relationships(
            principals, ["arn:aws:s3:::testbucket"],
            [{"permission": "S3:GetObject"}, {"permission": "S3:ListObject"}],
            {"arn:aws:s3:::testbucket": None},
            "AND",
            {},
            False,
        ),
    )


def test_full_multiple_principal_skip_admins():
    principals = {
        "test_principals1": {
            "ListAllow": [{
                "action": [
                    "s3:listobject",
                    "dynamodb:query",
                ],
                "resource": [
                    "*",
                ],
                "effect": "Allow",
            }],
            "explicitallow": [{
                "action": [
                    "s3:getobject",
                ],
                "resource": [
                    "arn:aws:s3:::testbucket",
                ],
                "effect": "Allow",
            }],
        },
        "test_principal2": {
            "ListAllow": [{
                "action": [
                    "s3:List*",
                ],
                "resource": [
                    "*",
                ],
                "effect": "Allow",
            }],
            "PutAllow": [{
                "action": [
                    "s3:Put*",
                ],
                "resource": [
                    "arn:aws:s3:::testbucket",
                ],
                "effect": "Allow",
            }],
        },
    }
    assert 1 == len(
        permission_relationships.calculate_permission_relationships(
            principals,
            ["arn:aws:s3:::testbucket"],
            [{"permission": "S3:GetObject"}],
            {"arn:aws:s3:::testbucket": True},
            "OR",
            {"test_principals1": True},
            True,
        ),
    )


def test_single_comma():
    statements = [
        {
            "action": [
                "s3:?et*",
            ],
            "resource":["arn:aws:s3:::testbucke?"],
            "effect": "Allow",
        },
    ]
    assert (True, False) == permission_relationships.evaluate_policy_for_permission(
        statements, "arn:aws:s3:::testbucket", "S3:GetObject",
    )


def test_multiple_comma():
    statements = [
        {
            "action": [
                "s3:?et*",
            ],
            "resource":["arn:aws:s3:::????bucket"],
            "effect": "Allow",
        },
    ]
    assert (True, False) == permission_relationships.evaluate_policy_for_permission(
        statements, "arn:aws:s3:::testbucket", "S3:GetObject",
    )


def test_permission_file_load():
    mapping = permission_relationships.parse_permission_relationships_file(
        "cartography/data/permission_relationships.yaml",
    )
    assert mapping


def test_permission_file_load_exception():
    mapping = permission_relationships.parse_permission_relationships_file("notarealfile")
    assert not mapping


def test_permissions_list():
    ###
    # Tests that the an exception is thrown if the permissions is not a list
    ###
    try:
        assert not permission_relationships.principal_allowed_on_resource(
            GET_OBJECT_LOWERCASE_RESOURCE_WILDCARD, "arn:aws:s3:::testbucket", "S3:GetObject",
        )
        assert False
    except ValueError:
        assert True
