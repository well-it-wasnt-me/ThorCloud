import textwrap

GET_REPOS = [
    {
        'name': 'sample_repo',
        'nameWithOwner': 'example_org/sample_repo',
        'primaryLanguage': {
            'name': 'Python',
        },
        'url': 'https://github.com/example_org/sample_repo',
        'sshUrl': 'git@github.com:example_org/sample_repo.git',
        'createdAt': '2011-02-15T18:40:15Z',
        'description': 'My description',
        'updatedAt': '2020-01-02T20:10:09Z',
        'homepageUrl': '',
        'languages': {
            'totalCount': 1,
            'nodes': [
                {'name': 'Python'},
            ],
        },
        'defaultBranchRef': {
            'name': 'master',
            'id': 'branch_ref_id==',
        },
        'isPrivate': True,
        'isArchived': False,
        'isDisabled': False,
        'isLocked': True,
        'owner': {
            'url': 'https://github.com/example_org',
            'login': 'example_org',
            '__typename': 'Organization',
        },
        'collaborators': {'edges': [], 'nodes': []},
        'requirements': {'text': 'cartography\nhttplib2<0.7.0\njinja2\nlxml\n-e git+https://example.com#egg=foobar\nhttps://example.com/foobar.tar.gz\npip @ https://github.com/pypa/pip/archive/1.3.1.zip#sha1=da9234ee9982d4bbb3c72346a6de940a148ea686\n'},  # noqa
        'setupCfg': {
            'text': textwrap.dedent('''
                [options]
                install_requires =
                    neo4j
                    scipy!=1.20.0  # comment
            '''),
        },
    }, {
        'name': 'SampleRepo2',
        'nameWithOwner': 'example_org/SampleRepo2',
        'primaryLanguage': {
            'name': 'Python',
        },
        'url': 'https://github.com/example_org/SampleRepo2',
        'sshUrl': 'git@github.com:example_org/SampleRepo2.git',
        'createdAt': '2011-09-21T18:55:16Z',
        'description': 'Some other description',
        'updatedAt': '2020-07-03T00:25:25Z',
        'homepageUrl': 'http://example.com/',
        'languages': {
            'totalCount': 1,
            'nodes': [
                {'name': 'Python'},
            ],
        },
        'defaultBranchRef': {
            'name': 'master',
            'id': 'other_branch_ref_id==',
        },
        'isPrivate': False,
        'isArchived': False,
        'isDisabled': False,
        'isLocked': False,
        'owner': {
            'url': 'https://github.com/example_org',
            'login': 'example_org', '__typename': 'Organization',
        },
        'collaborators': None,
        'requirements': None,
        'setupCfg': None,
    },
    {
        'name': 'cartography',
        'nameWithOwner': 'lyft/cartography',
        'primaryLanguage': {'name': 'Python'},
        'url': 'https://github.com/lyft/cartography',
        'sshUrl': 'git@github.com:lyft/cartography.git',
        'createdAt': '2019-02-27T00:16:29Z',
        'description': 'One graph to rule them all',
        'updatedAt': '2020-09-02T18:35:17Z',
        'homepageUrl': '',
        'languages': {
            'totalCount': 2,
            'nodes': [{'name': 'Python'}, {'name': 'Makefile'}],
        },
        'defaultBranchRef': {
            'name': 'master',
            'id': 'putsomethinghere',
        },
        'isPrivate': False,
        'isArchived': False,
        'isDisabled': False,
        'isLocked': False,
        'owner': {
            'url': 'https://github.com/example_org',
            'login': 'example_org',
            '__typename': 'Organization',
        },
        'collaborators': {
            'edges': [
                {'permission': 'WRITE'},
                {'permission': 'WRITE'},
                {'permission': 'WRITE'},
                {'permission': 'WRITE'},
                {'permission': 'WRITE'},
            ],
            'nodes': [
                {
                    'url': 'https://github.com/marco-lancini',
                    'login': 'marco-lancini',
                    'name': 'Marco Lancini',
                    'email': 'm@example.com',
                    'company': 'ExampleCo',
                },
                {
                    'url': 'https://github.com/sachafaust',
                    'login': 'sachafaust',
                    'name': 'Sacha Faust',
                    'email': 's@example.com',
                    'company': 'ExampleCo',
                },
                {
                    'url': 'https://github.com/SecPrez',
                    'login': 'SecPrez',
                    'name': 'SecPrez',
                    'email': 'sec@example.com',
                    'company': 'ExampleCo',
                },
                {
                    'url': 'https://github.com/ramonpetgrave64',
                    'login': 'ramonpetgrave64',
                    'name': 'Ramon Petgrave',
                    'email': 'r@example.com',
                    'company': 'ExampleCo',
                },
                {
                    'url': 'https://github.com/roshinis78',
                    'login': 'roshinis78',
                    'name': 'Roshini Saravanakumar',
                    'email': 'ro@example.com',
                    'company': 'ExampleCo',
                },
            ],
        },
        'requirements': {
            'text': 'cartography==0.1.0\nhttplib2>=0.7.0\njinja2\nlxml\n# This is a comment line to be ignored\nokta==0.9.0',  # noqa
        },
        'setupCfg': {
            'text': textwrap.dedent('''
                [options]
                install_requires =
                    neo4j>=1.0.0
                    numpy!=1.20.0  # comment
                    okta
            '''),
        },
    },
]
