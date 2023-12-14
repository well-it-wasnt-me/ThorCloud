import datetime
from datetime import timezone as tz

INSTANCE_INFORMATION = [
    {
        'InstanceId': 'i-01',
        'PingStatus': 'Online',
        'LastPingDateTime': datetime.datetime(2022, 3, 14, 4, 56, 22, 962000, tzinfo=tz.utc),
        'AgentVersion': '3.1.1004.1',
        'IsLatestVersion': True,
        'PlatformType': 'Linux',
        'PlatformName': 'Amazon Linux',
        'PlatformVersion': '2',
        'ResourceType': 'EC2Instance',
        'IPAddress': '10.0.0.1',
        'ComputerName': 'ip-10-0-0-1.us-east-1.compute.internal',
        'AssociationStatus': 'Pending',
        'LastAssociationExecutionDate': datetime.datetime(2022, 3, 14, 4, 58, 28, 395000, tzinfo=tz.utc),
        'LastSuccessfulAssociationExecutionDate': datetime.datetime(2022, 3, 14, 4, 28, 28, 395000, tzinfo=tz.utc),
        'AssociationOverview': {
            'DetailedStatus': 'Pending',
            'InstanceAssociationStatusAggregatedCount': {
                'Pending': 1,
                'Success': 3,
            },
        },
        'SourceId': 'i-01',
        'SourceType': 'AWS::EC2::Instance',
    },
    {
        'InstanceId': 'i-02',
        'PingStatus': 'Online',
        'LastPingDateTime': datetime.datetime(2022, 3, 14, 4, 56, 22, 962000, tzinfo=tz.utc),
        'AgentVersion': '3.1.1004.0',
        'IsLatestVersion': False,
        'PlatformType': 'Linux',
        'PlatformName': 'Amazon Linux',
        'PlatformVersion': '2',
        'ResourceType': 'EC2Instance',
        'IPAddress': '10.0.0.2',
        'ComputerName': 'ip-10-0-0-2.us-east-1.compute.internal',
        'AssociationStatus': 'Pending',
        'LastAssociationExecutionDate': datetime.datetime(2022, 3, 14, 4, 58, 28, 395000, tzinfo=tz.utc),
        'LastSuccessfulAssociationExecutionDate': datetime.datetime(2022, 3, 14, 4, 28, 28, 395000, tzinfo=tz.utc),
        'AssociationOverview': {
            'DetailedStatus': 'Pending',
            'InstanceAssociationStatusAggregatedCount': {
                'Pending': 1,
                'Success': 3,
            },
        },
        'SourceId': 'i-02',
        'SourceType': 'AWS::EC2::Instance',
    },
]

INSTANCE_PATCHES = [
    {
        'Title': 'test.x86_64:0:4.2.46-34.amzn2',
        'CVEIds': 'CVE-2022-0000,CVE-2022-0001',
        'KBId': 'test.x86_64',
        'Classification': 'Security',
        'Severity': 'Medium',
        'State': 'Installed',
        'InstalledTime': datetime.datetime(2021, 11, 8, 20, 51, 18, tzinfo=tz.utc),
        '_instance_id': 'i-01',
    },
    {
        'Title': 'test.x86_64:0:4.2.46-34.amzn2',
        'CVEIds': 'CVE-2022-0000,CVE-2022-0001',
        'KBId': 'test.x86_64',
        'Classification': 'Security',
        'Severity': 'Medium',
        'State': 'Installed',
        'InstalledTime': datetime.datetime(2021, 11, 8, 20, 51, 18, tzinfo=tz.utc),
        '_instance_id': 'i-02',
    },
]
