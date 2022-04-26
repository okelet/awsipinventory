import argparse
import csv
import dataclasses
import importlib.metadata
import ipaddress
import json
import logging
import os
import re
import socket
import sys
import time
from dataclasses import dataclass
from pprint import pprint, pformat
from typing import Optional, List, Dict, Any
from typing.io import IO

import boto3
import jinja2
import yaml
from tabulate import tabulate

__version__ = importlib.metadata.version(__package__)

INTERFACE_AVAILABLE = "available"
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
OBJECT_TYPE_VPC_ENDPOINT = "vpc_endpoint"
OBJECT_TYPE_ROUTE53_RESOLVER = "route53_resolver"
OBJECT_TYPE_TRANSIT_GATEWAY = "transit_gateway"
OBJECT_TYPE_RDS_PROXY = "rds_proxy"


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
        self.vpc_cache_by_region: Dict[str, List[Dict[str, Any]]] = {}
        self.subnet_cache_by_region: Dict[str, List[Dict[str, Any]]] = {}
        self.ec2_cache_by_region: Dict[str, List[Dict[str, Any]]] = {}
        self.load_balancers_v1_cache_by_region: Dict[str, List[Dict[str, Any]]] = {}
        self.load_balancers_v2_cache_by_region: Dict[str, List[Dict[str, Any]]] = {}
        self.rds_cache_by_region: Dict[str, List[Dict[str, Any]]] = {}
        self.ecs_clusters_cache_by_region: Dict[str, List[Dict[str, Any]]] = {}
        self.ecs_tasks_cache_by_region: Dict[str, List[Dict[str, Any]]] = {}
        self.lambda_cache_by_region: Dict[str, List[Dict[str, Any]]] = {}
        self.route53_resolvers_endpoints_cache_by_region: Dict[str, List[Dict[str, Any]]] = {}
        self.transit_gateway_attachments_cache_by_region: Dict[str, List[Dict[str, Any]]] = {}
        self.transit_gateway_cache_by_region: Dict[str, List[Dict[str, Any]]] = {}

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
            interface_id=interface_id,
            interface_status=interface_status,
            interface_type=interface_type,
            interface_requested_id=interface_requester_id,
            interface_description=description,
            private_ip_address=private_ip_address,
            public_ip_address=public_ip_address,
        )

        # Try to guess the object type
        if interface_status == "available":
            ip_address.object_type = INTERFACE_AVAILABLE

        elif instance_id:
            # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html
            logger.debug(f"  Detected EC2 instance; loading info...")
            ip_address.object_type = OBJECT_TYPE_INSTANCE
            ip_address.object_service_url = f"https://console.aws.amazon.com/ec2/v2/home?region={region}#Instances:"
            ip_address.object_id = instance_id
            ip_address.object_console_url = f"https://console.aws.amazon.com/ec2/v2/home?region={region}#Instances:search={instance_id};sort=instanceId"
            if self.ec2_cache_by_region.get(aws_session.region_name) is None:
                logger.debug(f"  Caching EC2 instances for region {region}...")
                start = time.time()
                self.ec2_cache_by_region[aws_session.region_name] = []
                for reservation in aws_session.client("ec2").get_paginator("describe_instances").paginate().build_full_result().get("Reservations"):
                    self.ec2_cache_by_region[aws_session.region_name].extend(reservation.get("Instances"))
                logger.debug(f"  EC2 instances cache loaded in {(time.time() - start):.2f} secs.")

            instance_data = next((x for x in self.ec2_cache_by_region[aws_session.region_name] if x.get("InstanceId") == instance_id), None)
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

        elif description and description.startswith("ELB "):
            # Description can be like:
            # - ELB awseb-e-u-AWSEBLoa-zzz (classic)
            # - ELB app/awseb-AWSEB-xxx/yyy -> only awseb-... is the real name (application)
            logger.debug(f"  Detected ELB; loading info...")
            ip_address.object_type = OBJECT_TYPE_ELB
            ip_address.object_service_url = f"https://console.aws.amazon.com/ec2/v2/home?region={region}#LoadBalancers:sort=loadBalancerName"
            load_balancer_name = re.sub("^ELB ", "", description)

            if load_balancer_name.startswith("app/") or load_balancer_name.startswith("net/"):
                load_balancer_name = load_balancer_name.split("/")[1]
                ip_address.object_type = OBJECT_TYPE_ELBv2
                if self.load_balancers_v2_cache_by_region.get(aws_session.region_name) is None:
                    logger.debug(f"  Caching ELBv2 for region {region}...")
                    start = time.time()
                    elb_v2_client = aws_session.client("elbv2")
                    self.load_balancers_v2_cache_by_region[aws_session.region_name] = elb_v2_client.get_paginator('describe_load_balancers').paginate().build_full_result().get("LoadBalancers")
                    for chunk in chunks(self.load_balancers_v2_cache_by_region[aws_session.region_name], 20):
                        for balancer_tags in elb_v2_client.describe_tags(ResourceArns=[x.get("LoadBalancerArn") for x in chunk]).get("TagDescriptions"):
                            next((x for x in self.load_balancers_v2_cache_by_region[aws_session.region_name] if x.get("LoadBalancerArn") == balancer_tags.get("ResourceArn")))["Tags"] = balancer_tags.get("Tags")
                    logger.debug(f"  ELBv2 cache loaded in {(time.time() - start):.2f} secs.")
                load_balancer = next((x for x in self.load_balancers_v2_cache_by_region.get(aws_session.region_name) if x.get("LoadBalancerName") == load_balancer_name), None)
            else:
                if self.load_balancers_v1_cache_by_region.get(aws_session.region_name) is None:
                    logger.debug(f"  Caching ELBv1 for region {region}...")
                    start = time.time()
                    elb_v1_client = aws_session.client("elb")
                    self.load_balancers_v1_cache_by_region[aws_session.region_name] = elb_v1_client.get_paginator('describe_load_balancers').paginate().build_full_result().get("LoadBalancerDescriptions")
                    for chunk in chunks(self.load_balancers_v1_cache_by_region[aws_session.region_name], 20):
                        for balancer_tags in elb_v1_client.describe_tags(LoadBalancerNames=[x.get("LoadBalancerName") for x in chunk]).get("TagDescriptions"):
                            next((x for x in self.load_balancers_v1_cache_by_region[aws_session.region_name] if x.get("LoadBalancerName") == balancer_tags.get("LoadBalancerName")))["Tags"] = balancer_tags.get("Tags")
                    logger.debug(f"  ELBv1 cache loaded in {(time.time() - start):.2f} secs.")
                load_balancer = next((x for x in self.load_balancers_v1_cache_by_region.get(aws_session.region_name) if x.get("LoadBalancerName") == load_balancer_name), None)

            if load_balancer:
                ip_address.object_tag_project = get_tag_value(load_balancer["Tags"], "project")
                ip_address.object_tag_environment = get_tag_value(load_balancer["Tags"], "environment")
                if load_balancer_name.startswith("awseb-"):
                    # This a LB associated with an Elastic Beanstalk environment
                    # Load name from tag elasticbeanstalk:environment-name, that contains the environment name
                    ip_address.object_name = get_tag_value(load_balancer["Tags"], "elasticbeanstalk:environment-name")

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

            if self.rds_cache_by_region.get(aws_session.region_name) is None:
                logger.debug(f"  Caching basic RDS instances information for region {region}...")
                start = time.time()
                self.rds_cache_by_region[aws_session.region_name] = aws_session.client("rds").get_paginator("describe_db_instances").paginate().build_full_result().get("DBInstances")
                logger.debug(f"  Basic RDS instances information cache loaded in {(time.time() - start):.2f} secs.")

            # Search for any instance whose resolved endpoint is the same as the public/private ip address
            # of the interface (depending if the instance is publicly accessible or not)
            instance_data = None
            for db_instance in self.rds_cache_by_region[aws_session.region_name]:
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

            if not self.ecs_tasks_cache_by_region.get(aws_session.region_name):
                logger.debug(f"  Caching ECS tasks for region {region}...")
                self.ecs_tasks_cache_by_region[aws_session.region_name] = []
                ecs_task_start = time.time()
                ecs_client = aws_session.client("ecs")
                for cluster_arn in ecs_client.get_paginator("list_clusters").paginate().build_full_result().get("clusterArns"):
                    task_arns = ecs_client.get_paginator("list_tasks").paginate(cluster=cluster_arn).build_full_result().get("taskArns")
                    for chunk in chunks(task_arns, 100):
                        self.ecs_tasks_cache_by_region[aws_session.region_name].extend(ecs_client.describe_tasks(cluster=cluster_arn, tasks=list(chunk)).get("tasks"))
                logger.debug(f"  ECS task cache loaded in {(time.time() - ecs_task_start):.2f} secs.")

            for task in self.ecs_tasks_cache_by_region[aws_session.region_name]:
                task_group = task.get("group")
                if task_group.startswith("service:"):
                    task_group = task_group[8:]
                else:
                    task_group = None
                for attachment in task.get("attachments"):
                    if attachment.get("id") == interface_id:
                        tags = task.get("tags")
                        cluster_name = task.get("clusterArn").split("/")[-1]
                        task_id = task.get("taskArn").split("/")[-1]
                        ip_address.object_id = task_id
                        ip_address.object_name = f"{cluster_name} / {task_group} / {task_id}"
                        ip_address.object_console_url = f"https://console.aws.amazon.com/ecs/home?region={region}#/clusters/{cluster_name}/tasks/{task_id}/details"
                        ip_address.object_tag_project = get_tag_value(tags, "project")
                        ip_address.object_tag_environment = get_tag_value(tags, "environment")
                        ip_address.object_description = get_tag_value(tags, "description")

        elif description and description.startswith("Interface for NAT Gateway nat-"):
            logger.debug(f"  Detected NAT gateway; loading info...")
            ip_address.object_type = OBJECT_TYPE_NAT_GATEWAY
            ip_address.object_service_url = f"https://console.aws.amazon.com/vpc/home?region={region}#NatGateways:"
            ip_address.object_id = re.sub("^Interface for NAT Gateway ", "", description)
            for nat_gateway in aws_session.client("ec2").get_paginator("describe_nat_gateways").paginate(NatGatewayIds=[ip_address.object_id]).build_full_result().get("NatGateways"):
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
            fs_data = next(iter(aws_session.client("efs").describe_file_systems(FileSystemId=fs_id).get("FileSystems")), None)
            if fs_data:
                ip_address.object_name = fs_data.get("Name")
                ip_address.object_tag_project = get_tag_value(fs_data.get("Tags"), "project")
                ip_address.object_tag_environment = get_tag_value(fs_data.get("Tags"), "environment")
                ip_address.object_description = get_tag_value(fs_data.get("Tags"), "description")

        elif description and description.startswith("AWS created network interface for directory d-"):
            logger.debug(f"  Detected Directory; loading info...")
            ip_address.object_type = OBJECT_TYPE_DIRECTORY
            ip_address.object_service_url = f"https://console.aws.amazon.com/directoryservicev2/home?region={region}#!/directories"
            ip_address.object_id = re.sub("^AWS created network interface for directory ", "", description)
            ip_address.object_console_url = f"https://console.aws.amazon.com/directoryservicev2/home?region={region}#!/directories/{ip_address.object_id}"
            ds_client = aws_session.client("ds")
            directory_info = next(iter(ds_client.get_paginator('describe_directories').paginate(DirectoryIds=[ip_address.object_id]).build_full_result().get("DirectoryDescriptions")), None)
            if directory_info:
                ip_address.object_name = directory_info.get("ShortName")
                ip_address.object_description = directory_info.get("Description")
                tags = ds_client.get_paginator("list_tags_for_resource").paginate(ResourceId=ip_address.object_id).build_full_result().get("Tags")
                ip_address.object_tag_project = get_tag_value(tags, "Project")
                ip_address.object_tag_environment = get_tag_value(tags, "Environment")

        elif description and description.startswith("Created By Amazon Workspaces for AWS Account ID"):
            logger.debug(f"  Detected Workspace; loading info...")
            ip_address.object_type = OBJECT_TYPE_WORKSPACE
            ip_address.object_service_url = f"https://console.aws.amazon.com/workspaces/home?region={region}#listworkspaces:"
            workspaces_client = aws_session.client("workspaces")
            for workspace_data in workspaces_client.get_paginator("describe_workspaces").paginate().build_full_result().get("Workspaces"):
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

            if self.lambda_cache_by_region.get(aws_session.region_name) is None:
                logger.debug(f"  Caching basic Lambda functions information for region {region}...")
                start = time.time()
                self.lambda_cache_by_region[aws_session.region_name] = aws_session.client("lambda").get_paginator('list_functions').paginate().build_full_result().get("Functions")
                logger.debug(f"  Basic Lambda functions information cache loaded in {(time.time() - start):.2f} secs.")

            lambda_function = next((x for x in self.lambda_cache_by_region[aws_session.region_name] if x.get("FunctionName") == ip_address.object_id), None)
            if lambda_function:
                tags = aws_session.client("lambda").list_tags(Resource=lambda_function.get("FunctionArn")).get("Tags")
                ip_address.object_tag_project = get_tag_value(tags, "project")
                ip_address.object_tag_environment = get_tag_value(tags, "environment")

        elif ":AWSCodeBuild-" in interface_requester_id:
            logger.debug(f"  Detected Codebuild; loading info...")
            ip_address.object_type = OBJECT_TYPE_CODEBUILD
            ip_address.object_service_url = f"https://console.aws.amazon.com/codesuite/codebuild/projects?region={region}"
            # TODO: Load additional info

        elif description and description == "DMSNetworkInterface":
            logger.debug(f"  Detected DMSNetworkInterface; loading info...")
            ip_address.object_type = OBJECT_TYPE_DMS
            ip_address.object_service_url = f"https://console.aws.amazon.com/dms/v2/home?region={region}#dashboard"
            # TODO: Load additional info

        elif description and description.startswith("VPC Endpoint Interface vpce-"):
            logger.debug(f"  Detected VPC endpoint; loading info...")
            ip_address.object_type = OBJECT_TYPE_VPC_ENDPOINT
            ip_address.object_service_url = f"https://console.aws.amazon.com/vpc/home?region={region}#Endpoints:sort=vpcEndpointId"
            ip_address.object_id = re.sub("VPC Endpoint Interface ", "", description)
            ip_address.object_console_url = f"https://console.aws.amazon.com/vpc/home?region={region}#Endpoints:vpcEndpointId={ip_address.object_id};sort=vpcEndpointId"
            # TODO: Load additional info

        elif description and description.startswith("Route 53 Resolver: "):

            logger.debug(f"  Detected Route53 resolver; loading info...")
            ip_address.object_type = OBJECT_TYPE_ROUTE53_RESOLVER
            ip_address.object_service_url = f"https://console.aws.amazon.com/route53resolver/home?region={region}#/vpc/{ip_address.vpc_id}"
            resolver_description = re.sub("Route 53 Resolver: ", "", description)
            ip_address.object_id = resolver_description.split(":")[0]
            ip_address.object_console_url = f"https://console.aws.amazon.com/route53resolver/home?region={region}#/endpoint/{ip_address.object_id}"

            if self.route53_resolvers_endpoints_cache_by_region.get(aws_session.region_name) is None:
                self.route53_resolvers_endpoints_cache_by_region[aws_session.region_name] = aws_session.client("route53resolver").get_paginator('list_resolver_endpoints').paginate().build_full_result().get("ResolverEndpoints")

            resolver_endpoint = next((x for x in self.route53_resolvers_endpoints_cache_by_region[aws_session.region_name] if x.get("Id") == ip_address.object_id), None)
            if resolver_endpoint:
                ip_address.object_name = resolver_endpoint.get("Name")
                tags = aws_session.client("route53resolver").get_paginator('list_tags_for_resource').paginate(ResourceArn=resolver_endpoint.get("Arn")).build_full_result().get("Tags")
                ip_address.object_tag_project = get_tag_value(tags, "Project")
                ip_address.object_tag_environment = get_tag_value(tags, "Environment")

        elif description and description.startswith("Network Interface for Transit Gateway Attachment "):

            logger.debug(f"  Detected Transit Gateway; loading info...")
            ip_address.object_type = OBJECT_TYPE_TRANSIT_GATEWAY
            ip_address.object_service_url = f"https://console.aws.amazon.com/directconnect/v2/home?region={region}#/transit-gateways"

            attachment_id = re.sub("Network Interface for Transit Gateway Attachment ", "", description)
            if self.transit_gateway_attachments_cache_by_region.get(aws_session.region_name) is None:
                self.transit_gateway_attachments_cache_by_region[aws_session.region_name] = aws_session.client("ec2").get_paginator('describe_transit_gateway_attachments').paginate().build_full_result().get("TransitGatewayAttachments")
            transit_gateway_attachment = next((x for x in self.transit_gateway_attachments_cache_by_region[aws_session.region_name] if x.get("TransitGatewayAttachmentId") == attachment_id), None)

            if transit_gateway_attachment:
                ip_address.object_id = transit_gateway_attachment.get("TransitGatewayId")
                if self.transit_gateway_cache_by_region.get(aws_session.region_name) is None:
                    self.transit_gateway_cache_by_region[aws_session.region_name] = aws_session.client("ec2").get_paginator('describe_transit_gateways').paginate().build_full_result().get("TransitGateways")
                transit_gateway = next((x for x in self.transit_gateway_cache_by_region[aws_session.region_name] if x.get("TransitGatewayId") == transit_gateway_attachment.get("TransitGatewayId")), None)
                if transit_gateway:
                    ip_address.object_console_url = f"https://console.aws.amazon.com/directconnect/v2/home?region={region}#/transit-gateways/{transit_gateway.get('TransitGatewayArn').replace(':transit-gateway/', ':')}"
                    tags = transit_gateway.get("Tags")
                    ip_address.object_name = get_tag_value(tags, "Name") or transit_gateway.get("Description")
                    ip_address.object_description = transit_gateway.get("Description")
                    ip_address.object_tag_project = get_tag_value(tags, "Project")
                    ip_address.object_tag_environment = get_tag_value(tags, "Environment")

        elif description and description.startswith("Network interface for DBProxy "):

            # No tags, this type of object doesn't support tags
            logger.debug(f"  Detected RDS proxy; loading info...")
            ip_address.object_type = OBJECT_TYPE_RDS_PROXY
            ip_address.object_service_url = f"https://console.aws.amazon.com/rds/home?region={region}#proxies:"
            ip_address.object_id = re.sub("Network interface for DBProxy ", "", description)
            ip_address.object_console_url = f"https://console.aws.amazon.com/rds/home?region={region}#proxy:id={ip_address.object_id}"

        else:
            logger.warning(f"  Unknown object type for interface {interface_id} with private IP address {private_ip_address}")
            logger.debug(pformat(interface_data))
            ip_address.object_type = OBJECT_TYPE_UNKNOWN

        self.ip_list.append(ip_address)

    def cache_vpc(self, aws_session, force: Optional[bool] = False) -> None:
        if self.vpc_cache_by_region.get(aws_session.region_name) is None or force:
            self.vpc_cache_by_region[aws_session.region_name] = aws_session.client("ec2").get_paginator("describe_vpcs").paginate().build_full_result().get("Vpcs")

    def get_vpc_name(self, aws_session, vpc_id: str) -> Optional[str]:
        self.cache_vpc(aws_session)
        return get_tag_value(next((x for x in self.vpc_cache_by_region[aws_session.region_name] if x.get("VpcId") == vpc_id), {}).get("Tags"), "Name")

    def cache_subnet(self, aws_session, force: Optional[bool] = False) -> None:
        if self.subnet_cache_by_region.get(aws_session.region_name) is None or force:
            self.subnet_cache_by_region[aws_session.region_name] = aws_session.client("ec2").get_paginator("describe_subnets").paginate().build_full_result().get("Subnets")

    def get_subnet_name(self, aws_session, subnet_id: str) -> Optional[str]:
        self.cache_subnet(aws_session)
        return get_tag_value(next((x for x in self.subnet_cache_by_region.get(aws_session.region_name) if x.get("SubnetId") == subnet_id), {}).get("Tags"), "Name")

    def sorted_by_ip(self):
        return sorted(self.ip_list, key=lambda x: ipaddress.IPv4Address(x.private_ip_address))


@dataclass
class AwsIpAddress:

    region: str
    vpc_id: str
    vpc_name: Optional[str]
    subnet_id: str
    subnet_name: Optional[str]

    interface_id: str
    interface_status: str
    interface_type: str
    interface_requested_id: str
    interface_description: Optional[str]

    private_ip_address: str
    public_ip_address: Optional[str]

    object_type: Optional[str] = None
    object_id: Optional[str] = None
    object_name: Optional[str] = None
    object_tag_project: Optional[str] = None
    object_tag_environment: Optional[str] = None
    object_description: Optional[str] = None
    object_console_url: Optional[str] = None
    object_service_url: Optional[str] = None

    interface_link: Optional[str] = Optional[str]
    vpc_link: Optional[str] = Optional[str]
    subnet_link: Optional[str] = Optional[str]

    @property
    def interface_link(self) -> str:
        return f"https://console.aws.amazon.com/ec2/v2/home?region={self.region}#NetworkInterface:networkInterfaceId={self.interface_id}"

    @interface_link.setter
    def interface_link(self, _val):
        pass

    @property
    def vpc_link(self) -> str:
        return f"https://console.aws.amazon.com/vpc/home?region={self.region}#vpcs:VpcId={self.vpc_id};sort=VpcId"

    @vpc_link.setter
    def vpc_link(self, _val):
        pass

    @property
    def subnet_link(self) -> str:
        return f"https://console.aws.amazon.com/vpc/home?region={self.region}#subnets:SubnetId={self.subnet_id};sort=SubnetId"

    @subnet_link.setter
    def subnet_link(self, _val):
        pass


def main(logger: logging.Logger, format: Optional[str] = None, output: Optional[IO[str]] = None, regions: Optional[List[str]] = None, vpc_ids: Optional[List[str]] = None, subnet_ids: Optional[List[str]] = None):

    if output is None:
        output = sys.stdout

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
        for parameter in default_ssm_client.get_paginator('get_parameters_by_path').paginate(Path=f"/aws/service/global-infrastructure/services/ec2/regions").build_full_result().get("Parameters"):
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
    account_alias = next(iter(default_session.client("iam").get_paginator("list_account_aliases").paginate().build_full_result().get("AccountAliases")), None)

    ip_addresses = AwsIpAddressList()

    for region in regions_to_process:

        logger.debug(f"Processing region {region}...")
        aws_session = boto3.session.Session(region_name=region)
        ec2_client = aws_session.client("ec2")

        # subnet_ids = ["subnet-bf6888d4"]
        # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_network_interfaces
        logger.debug(f"Loading network interfaces...")
        args = {"Filters": []}
        if vpc_ids:
            args["Filters"].append({"Name": "vpc-id", "Values": vpc_ids})
        if subnet_ids:
            args["Filters"].append({"Name": "subnet-id", "Values": subnet_ids})
        network_interfaces = ec2_client.get_paginator('describe_network_interfaces').paginate(**args).build_full_result().get("NetworkInterfaces")
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
        for x in sorted(ip_addresses.ip_list, key=lambda ip: [ip.region, ip.vpc_name or "", ip.private_ip_address]):
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
        ), file=output)

    elif format == "html":

        templateEnv = jinja2.Environment(loader=jinja2.FileSystemLoader(searchpath=os.path.join(os.path.dirname(os.path.realpath(__file__)), "templates")))

        print(templateEnv.get_template("inventory.html").render(
            account_id=account_id,
            account_alias=account_alias,
            data=[dataclasses.asdict(x) for x in ip_addresses.ip_list],
            regions=regions_to_process,
            vpcs=vpc_ids,
            subnets=subnet_ids,
        ), file=output)

    elif format == "json":
        json.dump([dataclasses.asdict(x) for x in ip_addresses.ip_list], output, indent=4)

    elif format in ["yaml", "yml"]:
        yaml.dump([dataclasses.asdict(x) for x in ip_addresses.ip_list], output)

    elif format == "csv":

        writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
        writer.writerow([x.name for x in  dataclasses.fields(AwsIpAddress)])
        writer.writerows([dataclasses.asdict(x).values() for x in ip_addresses.ip_list])

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
    parser.add_argument('--version', action='version', version=__version__)
    args = parser.parse_args()

    logger.setLevel(getattr(logging, args.log_level))

    try:
        main(logger, args.format, args.output, args.regions, args.vpcs, args.subnets)
    except InvalidRegionException as ex:
        print(str(ex), file=sys.stderr)
        sys.exit(1)
