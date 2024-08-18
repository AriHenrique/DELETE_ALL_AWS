import argparse

import boto3


def delete_s3_buckets():
    s3 = boto3.resource('s3')
    for bucket in s3.buckets.all():
        try:
            bucket.objects.all().delete()
            bucket.delete()
            print(f'Deleted bucket: {bucket.name}')
        except Exception as e:
            print(f'Error deleting bucket {bucket.name}: {e}')


def delete_ec2_instances():
    ec2 = boto3.resource('ec2')
    for instance in ec2.instances.all():
        try:
            instance.terminate()
            print(f'Terminated instance: {instance.id}')
        except Exception as e:
            print(f'Error terminating instance {instance.id}: {e}')


def delete_access_keys(user_name):
    iam = boto3.client('iam')
    try:
        access_keys = iam.list_access_keys(UserName=user_name)['AccessKeyMetadata']
        for key in access_keys:
            iam.delete_access_key(UserName=user_name, AccessKeyId=key['AccessKeyId'])
            print(f'Deleted access key {key["AccessKeyId"]} for user {user_name}')
    except Exception as e:
        print(f'Error deleting access keys for user {user_name}: {e}')


def detach_policies_from_user(user_name):
    iam = boto3.client('iam')
    attached_policies = iam.list_attached_user_policies(UserName=user_name)['AttachedPolicies']
    for policy in attached_policies:
        iam.detach_user_policy(UserName=user_name, PolicyArn=policy['PolicyArn'])


def delete_login_profile(user_name):
    iam = boto3.client('iam')
    try:
        iam.delete_login_profile(UserName=user_name)
        print(f'Deleted login profile for user: {user_name}')
    except iam.exceptions.NoSuchEntityException:
        print(f'No login profile found for user: {user_name}')


def remove_user_from_groups(user_name):
    iam = boto3.client('iam')
    groups = iam.list_groups_for_user(UserName=user_name)['Groups']
    for group in groups:
        iam.remove_user_from_group(GroupName=group['GroupName'], UserName=user_name)


def delete_iam_users(exclude: str):
    iam = boto3.client('iam')
    try:
        users = iam.list_users()['Users']
        for user in users:
            user_name = user['UserName']
            if user_name != exclude:
                delete_access_keys(user_name)
                detach_policies_from_user(user_name)
                delete_login_profile(user_name)
                remove_user_from_groups(user_name)
                iam.delete_user(UserName=user_name)
                print(f'Deleted user: {user_name}')
            else:
                continue
    except Exception as e:
        print(f'Error deleting IAM users: {e}')


def detach_policies_from_group(group_name):
    iam = boto3.client('iam')
    attached_policies = iam.list_attached_group_policies(GroupName=group_name)['AttachedPolicies']
    for policy in attached_policies:
        iam.detach_group_policy(GroupName=group_name, PolicyArn=policy['PolicyArn'])


def delete_inline_policies_from_group(group_name):
    iam = boto3.client('iam')
    inline_policies = iam.list_group_policies(GroupName=group_name)['PolicyNames']
    for policy in inline_policies:
        iam.delete_group_policy(GroupName=group_name, PolicyName=policy)


def delete_iam_groups():
    iam = boto3.client('iam')
    try:
        groups = iam.list_groups()['Groups']
        for group in groups:
            group_name = group['GroupName']
            detach_policies_from_group(group_name)
            delete_inline_policies_from_group(group_name)
            iam.delete_group(GroupName=group_name)
            print(f'Deleted IAM group: {group_name}')
    except Exception as e:
        print(f'Error deleting IAM groups: {e}')


def detach_policies_from_role(role_name):
    iam = boto3.client('iam')
    attached_policies = iam.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
    for policy in attached_policies:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy['PolicyArn'])


def delete_inline_policies_from_role(role_name):
    iam = boto3.client('iam')
    inline_policies = iam.list_role_policies(RoleName=role_name)['PolicyNames']
    for policy in inline_policies:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy)


def delete_iam_roles():
    iam = boto3.client('iam')
    try:
        roles = iam.list_roles()['Roles']
        for role in roles:
            if 'AWSServiceRoleFor' not in role['RoleName']:  # Evita deletar roles de serviços gerenciados pela AWS
                detach_policies_from_role(role['RoleName'])
                delete_inline_policies_from_role(role['RoleName'])
                iam.delete_role(RoleName=role['RoleName'])
                print(f'Deleted IAM role: {role["RoleName"]}')
    except Exception as e:
        print(f'Error deleting IAM roles: {e}')


def delete_vpcs():
    ec2 = boto3.client('ec2')
    try:
        vpcs = ec2.describe_vpcs()['Vpcs']
        for vpc in vpcs:
            delete_vpc_resources(vpc['VpcId'])
            ec2.delete_vpc(VpcId=vpc['VpcId'])
            print(f'Deleted VPC: {vpc["VpcId"]}')
    except Exception as e:
        print(f'Error deleting VPCs: {e}')


def delete_vpc_resources(vpc_id):
    ec2 = boto3.client('ec2')
    # Delete subnets
    subnets = ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])['Subnets']
    for subnet in subnets:
        ec2.delete_subnet(SubnetId=subnet['SubnetId'])

    # Delete security groups
    security_groups = ec2.describe_security_groups(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])['SecurityGroups']
    for sg in security_groups:
        if sg['GroupName'] != 'default':
            ec2.delete_security_group(GroupId=sg['GroupId'])

    # Delete route tables
    route_tables = ec2.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])['RouteTables']
    for rt in route_tables:
        if not rt['Associations'][0]['Main']:
            ec2.delete_route_table(RouteTableId=rt['RouteTableId'])

    # Delete internet gateways
    internet_gateways = ec2.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}])[
        'InternetGateways']
    for igw in internet_gateways:
        ec2.detach_internet_gateway(InternetGatewayId=igw['InternetGatewayId'], VpcId=vpc_id)
        ec2.delete_internet_gateway(InternetGatewayId=igw['InternetGatewayId'])


def delete_rds_instances():
    rds = boto3.client('rds')
    try:
        instances = rds.describe_db_instances()['DBInstances']
        for instance in instances:
            rds.delete_db_instance(DBInstanceIdentifier=instance['DBInstanceIdentifier'], SkipFinalSnapshot=True)
            print(f'Deleted RDS instance: {instance["DBInstanceIdentifier"]}')
    except Exception as e:
        print(f'Error deleting RDS instances: {e}')


def delete_lambda_functions():
    lambda_client = boto3.client('lambda')
    try:
        functions = lambda_client.list_functions()['Functions']
        for function in functions:
            lambda_client.delete_function(FunctionName=function['FunctionName'])
            print(f'Deleted Lambda function: {function["FunctionName"]}')
    except Exception as e:
        print(f'Error deleting Lambda functions: {e}')


def delete_dynamodb_tables():
    dynamodb = boto3.client('dynamodb')
    try:
        tables = dynamodb.list_tables()['TableNames']
        for table in tables:
            dynamodb.delete_table(TableName=table)
            print(f'Deleted DynamoDB table: {table}')
    except Exception as e:
        print(f'Error deleting DynamoDB tables: {e}')


def delete_sqs_queues():
    sqs = boto3.client('sqs')
    try:
        queues = sqs.list_queues().get('QueueUrls', [])
        for queue_url in queues:
            sqs.delete_queue(QueueUrl=queue_url)
            print(f'Deleted SQS queue: {queue_url}')
    except Exception as e:
        print(f'Error deleting SQS queues: {e}')


def delete_sns_topics():
    sns = boto3.client('sns')
    try:
        topics = sns.list_topics()['Topics']
        for topic in topics:
            sns.delete_topic(TopicArn=topic['TopicArn'])
            print(f'Deleted SNS topic: {topic["TopicArn"]}')
    except Exception as e:
        print(f'Error deleting SNS topics: {e}')


def delete_secrets_manager_secrets():
    secrets_manager = boto3.client('secretsmanager')
    try:
        secrets = secrets_manager.list_secrets()['SecretList']
        for secret in secrets:
            secrets_manager.delete_secret(SecretId=secret['ARN'], ForceDeleteWithoutRecovery=True)
            print(f'Deleted secret: {secret["Name"]}')
    except Exception as e:
        print(f'Error deleting secrets from Secrets Manager: {e}')


def delete_cloudwatch_logs():
    logs = boto3.client('logs')
    try:
        log_groups = logs.describe_log_groups()['logGroups']
        for log_group in log_groups:
            logs.delete_log_group(logGroupName=log_group['logGroupName'])
            print(f'Deleted CloudWatch log group: {log_group["logGroupName"]}')
    except Exception as e:
        print(f'Error deleting CloudWatch log groups: {e}')


def delete_cloudwatch_alarms():
    cloudwatch = boto3.client('cloudwatch')
    try:
        alarms = cloudwatch.describe_alarms()['MetricAlarms']
        for alarm in alarms:
            cloudwatch.delete_alarms(AlarmNames=[alarm['AlarmName']])
            print(f'Deleted CloudWatch alarm: {alarm["AlarmName"]}')
    except Exception as e:
        print(f'Error deleting CloudWatch alarms: {e}')


def delete_identity_providers():
    iam = boto3.client('iam')
    try:
        providers = iam.list_open_id_connect_providers()['OpenIDConnectProviderList']
        for provider in providers:
            iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=provider['Arn'])
            print(f'Deleted OpenID Connect Provider: {provider["Arn"]}')

        saml_providers = iam.list_saml_providers()['SAMLProviderList']
        for provider in saml_providers:
            iam.delete_saml_provider(SAMLProviderArn=provider['Arn'])
            print(f'Deleted SAML Provider: {provider["Arn"]}')

    except Exception as e:
        print(f'Error deleting identity providers: {e}')


def delete_all_customer_managed_policies():
    iam = boto3.client('iam')
    try:
        policies = iam.list_policies(Scope='Local')['Policies']
        for policy in policies:
            versions = iam.list_policy_versions(PolicyArn=policy['Arn'])['Versions']
            # Delete non-default policy versions
            for version in versions:
                if not version['IsDefaultVersion']:
                    iam.delete_policy_version(PolicyArn=policy['Arn'], VersionId=version['VersionId'])
            iam.delete_policy(PolicyArn=policy['Arn'])
            print(f'Deleted customer managed policy: {policy["PolicyName"]}')
    except Exception as e:
        print(f'Error deleting customer managed policies: {e}')


def delete_inline_policies_from_all_entities():
    iam = boto3.client('iam')

    # Deletar políticas inline de usuários
    try:
        users = iam.list_users()['Users']
        for user in users:
            inline_policies = iam.list_user_policies(UserName=user['UserName'])['PolicyNames']
            for policy in inline_policies:
                iam.delete_user_policy(UserName=user['UserName'], PolicyName=policy)
                print(f'Deleted inline policy {policy} from user {user["UserName"]}')
    except Exception as e:
        print(f'Error deleting inline policies from users: {e}')

    # Deletar políticas inline de grupos
    try:
        groups = iam.list_groups()['Groups']
        for group in groups:
            inline_policies = iam.list_group_policies(GroupName=group['GroupName'])['PolicyNames']
            for policy in inline_policies:
                iam.delete_group_policy(GroupName=group['GroupName'], PolicyName=policy)
                print(f'Deleted inline policy {policy} from group {group["GroupName"]}')
    except Exception as e:
        print(f'Error deleting inline policies from groups: {e}')

    # Deletar políticas inline de roles
    try:
        roles = iam.list_roles()['Roles']
        for role in roles:
            inline_policies = iam.list_role_policies(RoleName=role['RoleName'])['PolicyNames']
            for policy in inline_policies:
                iam.delete_role_policy(RoleName=role['RoleName'], PolicyName=policy)
                print(f'Deleted inline policy {policy} from role {role["RoleName"]}')
    except Exception as e:
        print(f'Error deleting inline policies from roles: {e}')


def delete_all_glue_jobs():
    glue = boto3.client('glue')
    try:
        jobs = glue.get_jobs()['Jobs']
        for job in jobs:
            glue.delete_job(JobName=job['Name'])
            print(f'Deleted Glue job: {job["Name"]}')
    except Exception as e:
        print(f'Error deleting Glue jobs: {e}')


def delete_all_eventbridge_rules():
    eventbridge = boto3.client('events')
    try:
        rules = eventbridge.list_rules()['Rules']
        for rule in rules:
            eventbridge.remove_targets(Rule=rule['Name'], Ids=['*'])
            eventbridge.delete_rule(Name=rule['Name'])
            print(f'Deleted EventBridge rule: {rule["Name"]}')
    except Exception as e:
        print(f'Error deleting EventBridge rules: {e}')


def delete_all_codebuild_projects():
    codebuild = boto3.client('codebuild')
    try:
        projects = codebuild.list_projects()['projects']
        for project in projects:
            codebuild.delete_project(name=project)
            print(f'Deleted CodeBuild project: {project}')
    except Exception as e:
        print(f'Error deleting CodeBuild projects: {e}')


def delete_all_codecommit_repositories():
    codecommit = boto3.client('codecommit')
    try:
        repositories = codecommit.list_repositories()['repositories']
        for repo in repositories:
            codecommit.delete_repository(repositoryName=repo['repositoryName'])
            print(f'Deleted CodeCommit repository: {repo["repositoryName"]}')
    except Exception as e:
        print(f'Error deleting CodeCommit repositories: {e}')


def delete_all_codepipeline_pipelines():
    codepipeline = boto3.client('codepipeline')
    try:
        pipelines = codepipeline.list_pipelines()['pipelines']
        for pipeline in pipelines:
            codepipeline.delete_pipeline(name=pipeline['name'])
            print(f'Deleted CodePipeline pipeline: {pipeline["name"]}')
    except Exception as e:
        print(f'Error deleting CodePipeline pipelines: {e}')


def delete_all_codestar_projects():
    codestar = boto3.client('codestar')
    try:
        projects = codestar.list_projects()['projects']
        for project in projects:
            codestar.delete_project(id=project['projectId'])
            print(f'Deleted CodeStar project: {project["name"]}')
    except Exception as e:
        print(f'Error deleting CodeStar projects: {e}')


def delete_all_route53_hosted_zones():
    route53 = boto3.client('route53')
    try:
        hosted_zones = route53.list_hosted_zones()['HostedZones']
        for zone in hosted_zones:
            record_sets = route53.list_resource_record_sets(HostedZoneId=zone['Id'])['ResourceRecordSets']
            for record in record_sets:
                if record['Type'] != 'NS' and record['Type'] != 'SOA':
                    route53.change_resource_record_sets(
                        HostedZoneId=zone['Id'],
                        ChangeBatch={
                            'Changes': [
                                {
                                    'Action': 'DELETE',
                                    'ResourceRecordSet': record
                                }
                            ]
                        }
                    )
            route53.delete_hosted_zone(Id=zone['Id'])
            print(f'Deleted Route 53 hosted zone: {zone["Name"]}')
    except Exception as e:
        print(f'Error deleting Route 53 hosted zones: {e}')


def delete_all_ecr_repositories():
    ecr = boto3.client('ecr')
    try:
        repositories = ecr.describe_repositories()['repositories']
        for repo in repositories:
            ecr.delete_repository(repositoryName=repo['repositoryName'], force=True)
            print(f'Deleted ECR repository: {repo["repositoryName"]}')
    except Exception as e:
        print(f'Error deleting ECR repositories: {e}')


def delete_all_lakeformation_resources():
    lakeformation = boto3.client('lakeformation')
    glue = boto3.client('glue')

    try:
        # Remover permissões de recursos do Lake Formation
        permissions = lakeformation.list_permissions()['PrincipalResourcePermissions']
        for permission in permissions:
            lakeformation.revoke_permissions(
                Principal=permission['Principal'],
                Resource=permission['Resource'],
                Permissions=permission['Permissions']
            )
            print(f"Revoked permissions for resource: {permission['Resource']}")

        # Deletar databases e tables no Glue, que estão sob controle do Lake Formation
        databases = glue.get_databases()['DatabaseList']
        for database in databases:
            tables = glue.get_tables(DatabaseName=database['Name'])['TableList']
            for table in tables:
                glue.delete_table(DatabaseName=database['Name'], Name=table['Name'])
                print(f"Deleted table {table['Name']} from database {database['Name']}")
            glue.delete_database(Name=database['Name'])
            print(f"Deleted database: {database['Name']}")

        # Remover registros de catálogos
        data_lake_settings = lakeformation.get_data_lake_settings()
        lakeformation.put_data_lake_settings(DataLakeSettings={
            'DataLakeAdmins': []
        })
        print(f'Cleared Lake Formation administrators and settings')

    except Exception as e:
        print(f'Error deleting Lake Formation resources: {e}')


def delete_all_stepfunctions_state_machines():
    sfn = boto3.client('stepfunctions')
    try:
        state_machines = sfn.list_state_machines()['stateMachines']
        for sm in state_machines:
            sfn.delete_state_machine(stateMachineArn=sm['stateMachineArn'])
            print(f'Deleted Step Functions state machine: {sm["name"]}')
    except Exception as e:
        print(f'Error deleting Step Functions state machines: {e}')


def delete_all_dms_tasks():
    dms = boto3.client('dms')
    try:
        tasks = dms.describe_replication_tasks()['ReplicationTasks']
        for task in tasks:
            dms.delete_replication_task(ReplicationTaskArn=task['ReplicationTaskArn'])
            print(f'Deleted DMS task: {task["ReplicationTaskIdentifier"]}')
    except Exception as e:
        print(f'Error deleting DMS tasks: {e}')


def delete_all_dms_endpoints():
    dms = boto3.client('dms')
    try:
        endpoints = dms.describe_endpoints()['Endpoints']
        for endpoint in endpoints:
            dms.delete_endpoint(EndpointArn=endpoint['EndpointArn'])
            print(f'Deleted DMS endpoint: {endpoint["EndpointIdentifier"]}')
    except Exception as e:
        print(f'Error deleting DMS endpoints: {e}')


def delete_all_dms_replication_instances():
    dms = boto3.client('dms')
    try:
        instances = dms.describe_replication_instances()['ReplicationInstances']
        for instance in instances:
            dms.delete_replication_instance(ReplicationInstanceArn=instance['ReplicationInstanceArn'])
            print(f'Deleted DMS replication instance: {instance["ReplicationInstanceIdentifier"]}')
    except Exception as e:
        print(f'Error deleting DMS replication instances: {e}')


def delete_all_athena_databases():
    glue = boto3.client('glue')
    try:
        databases = glue.get_databases()['DatabaseList']
        for database in databases:
            tables = glue.get_tables(DatabaseName=database['Name'])['TableList']
            for table in tables:
                glue.delete_table(DatabaseName=database['Name'], Name=table['Name'])
                print(f"Deleted table {table['Name']} from database {database['Name']}")
            glue.delete_database(Name=database['Name'])
            print(f"Deleted database: {database['Name']}")
    except Exception as e:
        print(f'Error deleting Athena databases: {e}')


def delete_all_glue_crawlers():
    glue = boto3.client('glue')
    try:
        crawlers = glue.get_crawlers()['Crawlers']
        for crawler in crawlers:
            glue.delete_crawler(Name=crawler['Name'])
            print(f'Deleted Glue crawler: {crawler["Name"]}')
    except Exception as e:
        print(f'Error deleting Glue crawlers: {e}')


def delete_all_glue_connectors():
    glue = boto3.client('glue')
    try:
        connectors = glue.list_custom_entity_types()['CustomEntityTypes']
        for connector in connectors:
            glue.delete_custom_entity_type(Name=connector['Name'])
            print(f'Deleted Glue connector: {connector["Name"]}')
    except Exception as e:
        print(f'Error deleting Glue connectors: {e}')


def delete_all_ec2_key_pairs():
    ec2 = boto3.client('ec2')
    try:
        key_pairs = ec2.describe_key_pairs()['KeyPairs']
        for key_pair in key_pairs:
            ec2.delete_key_pair(KeyName=key_pair['KeyName'])
            print(f'Deleted EC2 key pair: {key_pair["KeyName"]}')
    except Exception as e:
        print(f'Error deleting EC2 key pairs: {e}')


def delete_all_ebs_volumes():
    ec2 = boto3.client('ec2')
    try:
        volumes = ec2.describe_volumes(Filters=[{'Name': 'status', 'Values': ['available']}])['Volumes']
        for volume in volumes:
            ec2.delete_volume(VolumeId=volume['VolumeId'])
            print(f'Deleted EBS volume: {volume["VolumeId"]}')
    except Exception as e:
        print(f'Error deleting EBS volumes: {e}')


def delete_all_efs_file_systems():
    efs = boto3.client('efs')
    try:
        file_systems = efs.describe_file_systems()['FileSystems']
        for fs in file_systems:
            efs.delete_file_system(FileSystemId=fs['FileSystemId'])
            print(f'Deleted EFS file system: {fs["FileSystemId"]}')
    except Exception as e:
        print(f'Error deleting EFS file systems: {e}')


def delete_all_resources(exclude: str):
    delete_all_ec2_key_pairs()
    delete_all_ebs_volumes()
    delete_all_efs_file_systems()
    delete_all_athena_databases()
    delete_all_glue_connectors()
    delete_all_glue_crawlers()
    delete_all_dms_tasks()
    delete_all_dms_endpoints()
    delete_all_dms_replication_instances()
    delete_all_glue_jobs()
    delete_all_eventbridge_rules()
    delete_all_codebuild_projects()
    delete_all_codecommit_repositories()
    delete_all_codepipeline_pipelines()
    delete_all_codestar_projects()
    delete_all_route53_hosted_zones()
    delete_all_ecr_repositories()
    delete_all_lakeformation_resources()
    delete_all_stepfunctions_state_machines()
    delete_identity_providers()
    delete_inline_policies_from_all_entities()
    delete_all_customer_managed_policies()
    delete_identity_providers()
    delete_s3_buckets()
    delete_ec2_instances()
    delete_iam_users(exclude)
    delete_iam_groups()
    delete_iam_roles()
    delete_rds_instances()
    delete_lambda_functions()
    delete_vpcs()
    delete_dynamodb_tables()
    delete_sqs_queues()
    delete_sns_topics()
    delete_secrets_manager_secrets()
    delete_cloudwatch_logs()
    delete_cloudwatch_alarms()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Delete AWS resources.')
    parser.add_argument('exclude_user', type=str, help='The IAM username to exclude from deletion.')

    args = parser.parse_args()

    delete_all_resources(args.exclude_user)
