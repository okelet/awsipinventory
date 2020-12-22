import argparse
import ipaddress
import json
import logging
import os
import re
import socket
import sys
import time
from dataclasses import dataclass
from pprint import pprint
from typing import Optional, List, Dict, Tuple

import boto3
import jinja2
import yaml
from botocore.exceptions import ClientError
from tabulate import tabulate

OBJECT_TYPE_UNKNOWN = "unknown"
OBJECT_TYPE_INSTANCE = "ec2"
OBJECT_TYPE_ELASTICACHE = "elasticache"
OBJECT_TYPE_DIRECTORY = "directory"
OBJECT_TYPE_NAT_GATEWAY = "nat_gateway"
OBJECT_TYPE_RDS = "rds"
OBJECT_TYPE_ELB = "elb"
OBJECT_TYPE_ELBv2 = "elbv2"
OBJECT_TYPE_EFS = "efs"
OBJECT_TYPE_ECS_TASK = "ecs_task"
OBJECT_TYPE_LAMBDA = "lambda"
OBJECT_TYPE_CODEBUILD = "codebuild"
OBJECT_TYPE_WORKSPACE = "workspace"
OBJECT_TYPE_API_GATEWAY_VPC_LINK = "api_gateway_vpc_link"
OBJECT_TYPE_DMS = "dms"


def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def get_tag_value(tags: Optional[List[Dict[str, str]]], tag_name: str) -> Optional[str]:
    if not tags:
        return None
    if isinstance(tags, list):
        return next((x.get("Value") for x in tags if x.get("Key").lower() == tag_name.lower()), None)
    if isinstance(tags, dict):
        return next((val for key, val in tags.items() if key.lower() == tag_name.lower()), None)
    return None


class InvalidRegionException(Exception):
    pass


class AwsIpAddressList:

    def __init__(self):
        self.ip_list: List[AwsIpAddress] = []
        self.vpc_cache: Dict[str, Optional[str]] = {}
        self.subnet_cache: Dict[str, Optional[str]] = {}
        self.ecs_task_cache: Dict[str, Tuple[str, str]] = {}

    def add_from_data(self, logger: logging.Logger, aws_session, interface_data):

        region = aws_session.region_name
        description: Optional[str] = interface_data.get("Description") or None
        vpc_id: str = interface_data.get("VpcId")
        subnet_id: str = interface_data.get("SubnetId")
        private_ip_address: str = interface_data.get("PrivateIpAddress")
        public_ip_address: Optional[str] = interface_data.get("Association", {}).get("PublicIp")
        interface_id: str = interface_data.get("NetworkInterfaceId")
        interface_status: str = interface_data.get("Status")
        interface_type: str = interface_data.get("InterfaceType")
        interface_requester_id: str = interface_data.get("RequesterId")
        instance_id: Optional[str] = interface_data.get("Attachment", {}).get("InstanceId")

        ip_address = AwsIpAddress(
            region=region,
            vpc_id=vpc_id,
            vpc_name=self.get_vpc_name(aws_session, vpc_id),
            subnet_id=subnet_id,
            subnet_name=self.get_subnet_name(aws_session, subnet_id),
            private_ip_address=private_ip_address,
            public_ip_address=public_ip_address,
            interface_id=interface_id,
            interface_status=interface_status,
            interface_type=interface_type,
            interface_requested_id=interface_requester_id,
            interface_description=description,
        )

        # Try to guess the object type
        if instance_id:
            # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html
            logger.debug(f"  Detected EC2 instance; loading info...")
            ip_address.object_type = OBJECT_TYPE_INSTANCE
            ip_address.object_service_url = f"https://console.aws.amazon.com/ec2/v2/home?region={region}#Instances:"
            ip_address.object_id = instance_id
            ip_address.object_console_url = f"https://console.aws.amazon.com/ec2/v2/home?region={region}#Instances:search={instance_id};sort=instanceId"
            instance_data = None
            for page in aws_session.client("ec2").get_paginator("describe_instances").paginate(InstanceIds=[instance_id]):
                for reservation in page.get("Reservations"):
                    for instance in reservation.get("Instances"):
                        instance_data = instance
            if instance_data:
                ip_address.object_name = get_tag_value(instance_data.get("Tags"), "name")
                ip_address.object_tag_project = get_tag_value(instance_data.get("Tags"), "project")
                ip_address.object_tag_environment = get_tag_value(instance_data.get("Tags"), "environment")
                ip_address.object_description = get_tag_value(instance_data.get("Tags"), "description")

        elif interface_requester_id == "amazon-elasticache" and description:
            # Description can be like:
            # - ElastiCache xxx-0001-001
            logger.debug(f"  Detected Elasticache; loading info...")
            ip_address.object_type = OBJECT_TYPE_ELASTICACHE
            ip_address.object_service_url = f"https://console.aws.amazon.com/elasticache/home?region={region}#"
            ip_address.object_id = re.sub("^ElastiCache ", "", description)
            # ip_address.object_console_url = f"https://console.aws.amazon.com/ec2/v2/home?region=us-east-1#LoadBalancers:search={load_balancer_name};sort=loadBalancerName"
            # TODO: Load tags

        elif interface_requester_id == "amazon-elb" and description:
            # Description can be like:
            # - ELB awseb-e-u-AWSEBLoa-zzz (classic)
            # - ELB app/awseb-AWSEB-xxx/yyy -> only awseb-... is the real name (application)
            logger.debug(f"  Detected ELB; loading info...")
            ip_address.object_type = OBJECT_TYPE_ELB
            ip_address.object_service_url = f"https://console.aws.amazon.com/ec2/v2/home?region={region}#LoadBalancers:sort=loadBalancerName"
            load_balancer_name = re.sub("^ELB ", "", description)

            tags = None
            if load_balancer_name.startswith("app/"):
                load_balancer_name = load_balancer_name.split("/")[1]
                ip_address.object_type = OBJECT_TYPE_ELBv2
                elb_v2_client = aws_session.client("elbv2")
                load_balancers = elb_v2_client.get_paginator('describe_load_balancers').paginate(Names=[load_balancer_name]).build_full_result().get("LoadBalancers")
                if load_balancers:
                    load_balancer = load_balancers[0]
                    load_balancer_arn = load_balancer.get("LoadBalancerArn")
                    tags = elb_v2_client.describe_tags(ResourceArns=[load_balancer_arn]).get("TagDescriptions")[0].get("Tags")
            else:
                elb_client = aws_session.client("elb")
                # Get the load balancer to ensure that it exists
                load_balancers = elb_client.get_paginator("describe_load_balancers").paginate(LoadBalancerNames=[load_balancer_name]).build_full_result().get("LoadBalancerDescriptions")
                if load_balancers:
                    tags = elb_client.describe_tags(LoadBalancerNames=[load_balancer_name]).get("TagDescriptions")[0].get("Tags")

            ip_address.object_tag_project = get_tag_value(tags, "project")
            ip_address.object_tag_environment = get_tag_value(tags, "environment")
            if load_balancer_name.startswith("awseb-"):
                # This a LB associated with an Elastic Beanstalk environment
                # Load name from tag elasticbeanstalk:environment-name, that contains the environment name
                ip_address.object_name = get_tag_value(tags, "elasticbeanstalk:environment-name")

            ip_address.object_id = load_balancer_name
            ip_address.object_console_url = f"https://console.aws.amazon.com/ec2/v2/home?region={region}#LoadBalancers:search={load_balancer_name};sort=loadBalancerName"

        elif interface_type == "api_gateway_managed":
            ip_address.object_type = OBJECT_TYPE_API_GATEWAY_VPC_LINK
            ip_address.object_service_url = f"https://eu-west-1.console.aws.amazon.com/apigateway/main/vpc-links/list?region={region}"
            ip_address.object_id = get_tag_value(interface_data.get("TagSet"), "VpcLinkId")
            ip_address.object_console_url = f"https://eu-west-1.console.aws.amazon.com/apigateway/main/vpc-links/list?region={region}&vpcLink={ip_address.object_id}"
            vpc_link = aws_session.client("apigatewayv2").get_vpc_link(VpcLinkId=ip_address.object_id)
            ip_address.object_name = vpc_link.get("Name")
            tags = vpc_link.get("Tags")
            ip_address.object_tag_project = get_tag_value(tags, "project")
            ip_address.object_tag_environment = get_tag_value(tags, "environment")

        elif description == "RDSNetworkInterface" or (interface_requester_id == "amazon-rds" and description):

            # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds.html
            logger.debug(f"  Detected RDS instance; loading info...")
            ip_address.object_type = OBJECT_TYPE_RDS
            ip_address.object_service_url = f"https://console.aws.amazon.com/rds/home?region={region}#"
            instance_data = None

            # Search for any instance whose reolved endpoint is the same as the public/private ip address
            # of the interface (depending if the instance is publicly accessible or not)
            for page in aws_session.client("rds").get_paginator("describe_db_instances").paginate():
                for db_instance in page.get("DBInstances"):
                    public = db_instance.get("PubliclyAccessible")
                    if db_instance.get("DBSubnetGroup", {}).get("VpcId") == vpc_id:
                        endpoint = db_instance.get("Endpoint", {}).get("Address")
                        if endpoint:
                            endpoint_ip = socket.gethostbyname(endpoint)
                            if endpoint_ip:
                                if public and public_ip_address and endpoint_ip == public_ip_address:
                                    instance_data = db_instance
                                    break
                                elif not public and private_ip_address and endpoint_ip == private_ip_address:
                                    instance_data = db_instance
                                    break
            if instance_data:
                ip_address.object_id = instance_data.get("DBInstanceIdentifier")
                arn = instance_data.get("DBInstanceArn")
                tags = aws_session.client("rds").list_tags_for_resource(ResourceName=arn).get("TagList")
                ip_address.object_tag_project = get_tag_value(tags, "project")
                ip_address.object_tag_environment = get_tag_value(tags, "environment")
                ip_address.object_description = get_tag_value(tags, "description")
                ip_address.object_console_url = f"https://console.aws.amazon.com/rds/home?region={region}#database:id={ip_address.object_id};is-cluster=false"

        elif description and description.startswith("arn:aws:ecs:"):

            logger.debug(f"  Detected ECS task; loading info...")
            ip_address.object_type = OBJECT_TYPE_ECS_TASK
            ip_address.object_service_url = f"https://console.aws.amazon.com/ecs/home?region={region}#/clusters"
            interface_id = description.split("/")[-1]
            task_info = self.ecs_task_cache.get(region, {}).get(interface_id)

            if not task_info and self.ecs_task_cache.get(region) is None:
                logger.debug(f"  Loading ECS task cache for region {region}...")
                ecs_task_start = time.time()
                self.ecs_task_cache[region] = {}
                cluster_arns = []
                for cluster_page in aws_session.client("ecs").get_paginator("list_clusters").paginate():
                    cluster_arns.extend(cluster_page.get("clusterArns"))
                for cluster_arn in cluster_arns:
                    task_arns = []
                    for page in aws_session.client("ecs").get_paginator("list_tasks").paginate(cluster=cluster_arn):
                        task_arns.extend(page.get("taskArns"))
                    for chunk in chunks(task_arns, 100):
                        for task in aws_session.client("ecs").describe_tasks(cluster=cluster_arn, tasks=list(chunk)).get("tasks"):
                            task_group = task.get("group")
                            tags = task.get("tags")
                            if task_group.startswith("service:"):
                                task_group = task_group[8:]
                            else:
                                task_group = None
                            for attachment in task.get("attachments"):
                                self.ecs_task_cache[region][attachment.get("id")] = (cluster_arn, task_group, task.get("taskArn"), get_tag_value(tags, "project"), get_tag_value(tags, "environment"), get_tag_value(tags, "description"))
                                if attachment.get("id") == interface_id:
                                    # Don't break after finding the searched task, so we build the cache
                                    task_info = self.ecs_task_cache[region][interface_id]
                logger.debug(f"  ECS task cache loaded in {(time.time()-ecs_task_start):.2f} secs.")

            if task_info:
                (cluster_arn, task_group, task_arn, project, environment, description) = task_info
                cluster_name = cluster_arn.split("/")[-1]
                task_id = task_arn.split("/")[-1]
                ip_address.object_id = task_id
                ip_address.object_name = f"{cluster_name} / {task_group} / {task_id}"
                ip_address.object_console_url = f"https://console.aws.amazon.com/ecs/home?region={region}#/clusters/{cluster_name}/tasks/{task_id}/details"
                ip_address.object_tag_project = project
                ip_address.object_tag_environment = environment
                ip_address.object_description = description

        elif description and description.startswith("Interface for NAT Gateway nat-"):
            logger.debug(f"  Detected NAT gateway; loading info...")
            ip_address.object_type = OBJECT_TYPE_NAT_GATEWAY
            ip_address.object_service_url = f"https://console.aws.amazon.com/vpc/home?region={region}#NatGateways:"
            ip_address.object_id = re.sub("^Interface for NAT Gateway ", "", description)
            for page in aws_session.client("ec2").get_paginator("describe_nat_gateways").paginate(NatGatewayIds=[ip_address.object_id]):
                for nat_gateway in page.get("NatGateways"):
                    tags = nat_gateway.get("Tags")
                    ip_address.object_name = get_tag_value(tags, "name")
                    ip_address.object_tag_project = get_tag_value(tags, "project")
                    ip_address.object_tag_environment = get_tag_value(tags, "environment")
                    ip_address.object_description = get_tag_value(tags, "description")
            ip_address.object_console_url = f"https://console.aws.amazon.com/vpc/home?region={region}#NatGatewayDetails:natGatewayId={ip_address.object_id}"

        elif description and description.startswith("EFS mount target for fs-"):
            # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/efs.html
            logger.debug(f"  Detected EFS mount target; loading info...")
            fs_id = re.compile(".*(fs-[a-z0-9]*).*").match(description).group(1)
            ip_address.object_type = OBJECT_TYPE_EFS
            ip_address.object_service_url = f"https://console.aws.amazon.com/efs/home?region={region}#/file-systems"
            ip_address.object_id = fs_id
            ip_address.object_console_url = f"https://console.aws.amazon.com/efs/home?region={region}#/file-systems/{fs_id}"
            fs_data = aws_session.client("efs").describe_file_systems(FileSystemId=fs_id).get("FileSystems")
            if fs_data:
                ip_address.object_name = fs_data[0].get("Name")
                ip_address.object_tag_project = get_tag_value(fs_data[0].get("Tags"), "project")
                ip_address.object_tag_environment = get_tag_value(fs_data[0].get("Tags"), "environment")
                ip_address.object_description = get_tag_value(fs_data[0].get("Tags"), "description")

        elif description and description.startswith("AWS created network interface for directory d-"):
            logger.debug(f"  Detected Directory; loading info...")
            ip_address.object_type = OBJECT_TYPE_DIRECTORY
            ip_address.object_service_url = f"https://console.aws.amazon.com/directoryservicev2/home?region={region}#!/directories"
            ip_address.object_id = re.sub("^AWS created network interface for directory ", "", description)
            ip_address.object_console_url = f"https://console.aws.amazon.com/directoryservicev2/home?region={region}#!/directories/{ip_address.object_id}"
            for page in aws_session.client("ds").get_paginator('describe_directories').paginate(DirectoryIds=[ip_address.object_id]):
                for directory in page.get("DirectoryDescriptions"):
                    ip_address.object_name = directory.get("ShortName")
                    ip_address.object_description = directory.get("Description")
            # TODO: Load tags

        elif description and description.startswith("Created By Amazon Workspaces for AWS Account ID"):
            logger.debug(f"  Detected Workspace; loading info...")
            ip_address.object_type = OBJECT_TYPE_WORKSPACE
            ip_address.object_service_url = f"https://console.aws.amazon.com/workspaces/home?region={region}#listworkspaces:"
            workspaces_client = aws_session.client("workspaces")
            for page in workspaces_client.get_paginator("describe_workspaces").paginate():
                for workspace_data in page.get("Workspaces"):
                    if workspace_data.get("SubnetId") == subnet_id and workspace_data.get("IpAddress") == private_ip_address:
                        ip_address.object_id = workspace_data.get("WorkspaceId")
                        ip_address.object_name = workspace_data.get("UserName")
                        ip_address.object_console_url = f"https://console.aws.amazon.com/workspaces/home?region={region}#listworkspaces:search={ip_address.object_id}"
                        tags = workspaces_client.describe_tags(ResourceId=workspace_data.get("WorkspaceId")).get("TagList")
                        ip_address.object_tag_project = get_tag_value(tags, "project")
                        ip_address.object_tag_environment = get_tag_value(tags, "environment")

        elif description and description.startswith("AWS Lambda VPC "):
            # Description is like
            # AWS Lambda VPC ENI-function-name-0eabb672-9699-4752-8738-38b7379f118b
            # So procedure is:
            # - Remove "AWS Lambda VPC ENI-"
            # - Reverse
            # - Remove the first 37 chars
            # - Reverse
            logger.debug(f"  Detected Lambda; loading info...")
            ip_address.object_type = OBJECT_TYPE_LAMBDA
            ip_address.object_service_url = f"https://console.aws.amazon.com/lambda/home?region={region}#/functions"
            ip_address.object_id = re.sub("AWS Lambda VPC ENI-", "", description)[::-1][37:][::-1]
            ip_address.object_console_url = f"https://console.aws.amazon.com/lambda/home?region={region}#/functions/{ip_address.object_id}?tab=configuration"
            lambda_client = aws_session.client("lambda")
            try:
                lambda_function = lambda_client.get_function(FunctionName=ip_address.object_id)
                tags = lambda_function.get("Tags")
                ip_address.object_tag_project = get_tag_value(tags, "project")
                ip_address.object_tag_environment = get_tag_value(tags, "environment")
            except ClientError as ex:
                if ex.response['Error']['Code'] == 'ResourceNotFoundException':
                    pass
                else:
                    raise ex

        elif ":AWSCodeBuild-" in interface_requester_id:
            logger.debug(f"  Detected Codebuild; loading info...")
            ip_address.object_type = OBJECT_TYPE_CODEBUILD
            ip_address.object_service_url = f"https://console.aws.amazon.com/codesuite/codebuild/projects?region={region}"

        elif description and description == "DMSNetworkInterface":
            logger.debug(f"  Detected DMSNetworkInterface; loading info...")
            ip_address.object_type = OBJECT_TYPE_DMS
            ip_address.object_service_url = f"https://console.aws.amazon.com/dms/v2/home?region={region}#dashboard"

        else:
            logger.warning(f"  Unknown object type for interface {interface_id} with private IP address {private_ip_address}")
            logger.debug(json.dumps(interface_data, indent=4))
            ip_address.object_type = OBJECT_TYPE_UNKNOWN

        self.ip_list.append(ip_address)

    def get_vpc_name(self, aws_session, vpc_id: str) -> Optional[str]:
        if vpc_id in self.vpc_cache.keys():
            return self.vpc_cache[vpc_id]
        vpc_data = aws_session.client("ec2").describe_vpcs(VpcIds=[vpc_id])
        if vpc_data.get("Vpcs", []):
            vpc_name = get_tag_value(vpc_data.get("Vpcs")[0].get("Tags"), "Name")
            self.vpc_cache[vpc_id] = vpc_name
        else:
            self.vpc_cache[vpc_id] = None
        return self.vpc_cache[vpc_id]

    def get_subnet_name(self, aws_session, subnet_id: str) -> Optional[str]:
        if subnet_id in self.subnet_cache.keys():
            return self.subnet_cache[subnet_id]
        subnet_data = aws_session.client("ec2").describe_subnets(SubnetIds=[subnet_id])
        if subnet_data.get("Subnets", []):
            subnet_name = get_tag_value(subnet_data.get("Subnets")[0].get("Tags"), "Name")
            self.subnet_cache[subnet_id] = subnet_name
        else:
            self.subnet_cache[subnet_id] = None
        return self.subnet_cache[subnet_id]

    def sorted_by_ip(self):
        return sorted(self.ip_list, key=lambda x: ipaddress.IPv4Address(x.private_ip_address))


@dataclass
class AwsIpAddress:

    region: str
    vpc_id: str
    vpc_name: Optional[str]
    subnet_id: str
    subnet_name: Optional[str]
    private_ip_address: str
    public_ip_address: Optional[str]
    interface_description: Optional[str]
    interface_id: str
    interface_status: str
    interface_type: str
    interface_requested_id: str

    object_type: Optional[str] = None
    object_id: Optional[str] = None
    object_name: Optional[str] = None
    object_tag_project: Optional[str] = None
    object_tag_environment: Optional[str] = None
    object_description: Optional[str] = None
    object_console_url: Optional[str] = None
    object_service_url: Optional[str] = None

    @property
    def vpc_link(self):
        return f"https://console.aws.amazon.com/vpc/home?region={self.region}#vpcs:VpcId={self.vpc_id};sort=VpcId"

    @property
    def subnet_link(self):
        return f"https://console.aws.amazon.com/vpc/home?region={self.region}#subnets:SubnetId={self.subnet_id};sort=SubnetId"

    def to_dict(self):
        return {
            "region": self.region,
            "interface_id": self.interface_id,
            "interface_type": self.interface_type,
            "interface_description": self.interface_description,
            "interface_requested_id": self.interface_requested_id,
            "interface_status": self.interface_status,
            "vpc_id": self.vpc_id,
            "vpc_name": self.vpc_name,
            "vpc_link": self.vpc_link,
            "subnet_id": self.subnet_id,
            "subnet_name": self.subnet_name,
            "subnet_link": self.subnet_link,
            "private_ip_address": self.private_ip_address,
            "public_ip_address": self.public_ip_address,
            "object_type": self.object_type,
            "object_id": self.object_id,
            "object_name": self.object_name,
            "object_tag_project": self.object_tag_project,
            "object_tag_environment": self.object_tag_environment,
            "object_description": self.object_description,
            "object_console_url": self.object_console_url,
            "object_service_url": self.object_service_url,
        }


def main(logger: logging.Logger, format: Optional[str], output: Optional[str], regions: Optional[List[str]], vpc_ids: Optional[List[str]], subnet_ids: Optional[List[str]], columns: Optional[List[str]]):

    default_session = boto3.session.Session()
    default_ec2_client = default_session.client("ec2")
    default_ssm_client = default_session.client("ssm")

    if regions:

        # Load regions that are allowed in the account, using EC2 and SSM
        logger.debug("Loading allowed regions...")
        account_allowed_regions = []
        for region_data in default_ec2_client.describe_regions(AllRegions=True).get("Regions", []):
            if region_data.get("OptInStatus") in ["opt-in-not-required", "opted-in"]:
                account_allowed_regions.append(region_data.get("RegionName"))

        ec2_regions = []
        for page in default_ssm_client.get_paginator('get_parameters_by_path').paginate(Path=f"/aws/service/global-infrastructure/services/ec2/regions"):
            for parameter in page.get("Parameters", []):
                region = parameter.get("Value")
                if region in account_allowed_regions:
                    ec2_regions.append(region)

        if "all" in regions:
            regions_to_process = ec2_regions
        else:
            for region in regions:
                if region not in ec2_regions:
                    raise InvalidRegionException(f"Region {region} is not valid")
            regions_to_process = regions

    else:
        # Use the current region
        regions_to_process = [default_session.region_name]

    account_info = default_session.client("sts").get_caller_identity()
    account_id = account_info.get("Account")

    logger.debug("Loading account alias...")
    account_alias = None
    for page in default_session.client("iam").get_paginator("list_account_aliases").paginate():
        if page.get("AccountAliases"):
            account_alias = page.get("AccountAliases")[0]
            break

    ip_addresses = AwsIpAddressList()

    for region in regions_to_process:

        logger.debug(f"Processing region {region}...")
        aws_session = boto3.session.Session(region_name=region)
        ec2_client = aws_session.client("ec2")

        # subnet_ids = ["subnet-bf6888d4"]
        # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_network_interfaces
        logger.debug(f"Loading network interfaces...")
        args = {"Filters": []}
        network_interfaces = []
        if vpc_ids:
            args["Filters"].append({"Name": "vpc-id", "Values": vpc_ids})
        if subnet_ids:
            args["Filters"].append({"Name": "subnet-id", "Values": subnet_ids})
        for page in ec2_client.get_paginator('describe_network_interfaces').paginate(**args):
            for interface_data in page.get("NetworkInterfaces", []):
                network_interfaces.append(interface_data)
        logger.debug(f"Loaded {len(network_interfaces)} interfaces.")

        for idx, interface_data in enumerate(network_interfaces, 1):
            logger.debug(f"Processing interface data {idx}/{len(network_interfaces)}...")
            ip_addresses.add_from_data(logger, aws_session, interface_data)

    logger.info("Generating output...")
    if format is None or format == "table":

        headers = [
            "VPC ID",
            "VPC name",
            "Subnet ID",
            "Subnet name",
            "Private IP address",
            "Public IP address",
            "Type",
            "ID",
            "Name",
            "Project",
            "Environment",
        ]

        if len(regions_to_process) > 1:
            headers.insert(0, "Region")

        data = []
        for x in sorted(ip_addresses.ip_list, key=lambda ip: [ip.region, ip.vpc_name, ip.private_ip_address]):
            ip_data = [
                x.vpc_id,
                x.vpc_name,
                x.subnet_id,
                x.subnet_name,
                x.private_ip_address,
                x.public_ip_address,
                x.object_type,
                x.object_id,
                x.object_name,
                x.object_tag_project,
                x.object_tag_environment,
            ]
            if len(regions_to_process) > 1:
                ip_data.insert(0, x.region)
            data.append(ip_data)

        print(tabulate(
            data,
            headers=headers,
            tablefmt="pretty",
            colalign="left",
        ))

    elif format == "html":

        templateEnv = jinja2.Environment(loader=jinja2.FileSystemLoader(searchpath=os.path.join(os.path.dirname(os.path.realpath(__file__)), "templates")))

        print(templateEnv.get_template("inventory.html").render(
            account_id=account_id,
            account_alias=account_alias,
            data=[x.to_dict() for x in ip_addresses.ip_list],
            regions=regions_to_process,
            vpcs=vpc_ids,
            subnets=subnet_ids,
        ), file=output)

    elif format == "json":
        print(json.dumps([x.to_dict() for x in ip_addresses.ip_list], indent=4))

    elif format in ["yaml", "yml"]:
        yaml.dump([x.to_dict() for x in ip_addresses.ip_list], sys.stdout)

    elif format == "csv":

        print(f"Output format {format} not yet implemented", file=sys.stderr)

    elif format == "none":
        # Do not output nothing (useful when debugging)
        pass


def cli():

    logging.basicConfig()
    logger = logging.getLogger(__name__)

    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--log-level", type=str.upper, choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], default="WARNING", help="Set the logging level")
    parser.add_argument("-f", "--format", choices=["none", "table", "html", "json", "yaml", "yml", "csv"], default="table", help="Output format")
    parser.add_argument("-o", "--output", type=argparse.FileType('w'), default=sys.stdout, help="Output file; defaults to standard output")
    parser.add_argument("--regions", nargs="*", help="Use \"all\" to get data from all enabled regions")
    parser.add_argument("--vpcs", nargs="*", help="Restrict results to specific VPCs (must exist in the account and regions)")
    parser.add_argument("--subnets", nargs="*", help="Restrict results to specific subnets (must exist in the account, VPCs and regions)")
    parser.add_argument("--columns", nargs="*")
    args = parser.parse_args()

    logger.setLevel(getattr(logging, args.log_level))

    try:
        main(logger, args.format, args.output, args.regions, args.vpcs, args.subnets, args.columns)
    except InvalidRegionException as ex:
        print(str(ex), file=sys.stderr)
        sys.exit(1)
