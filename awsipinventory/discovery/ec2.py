import logging
from typing import Any, Dict, Optional
from awsipinventory import AwsInterface
from awsipinventory.discovery import BaseInterfaceDetector


LOG = logging.getLOG(__name__)

class Ec2InterfaceDetector(BaseInterfaceDetector):
    """
    EC2 interface discovery.
    """
    @staticmethod
    def detect(interface_data: Dict[str, Any], interface: AwsInterface) -> bool:
        """
        Abstract method that the child classes must implement and return an object with the corresponding information.
        """
        instance_id = interface_data.get("Attachment", {}).get("InstanceId")
        if instance_id:
            LOG.debug("  Detected EC2 instance; loading info...")
            ip_address.object_type = OBJECT_TYPE_INSTANCE
            ip_address.object_service_url = f"https://console.aws.amazon.com/ec2/v2/home?region={region}#Instances:"
            ip_address.object_id = instance_id
            ip_address.object_console_url = f"https://console.aws.amazon.com/ec2/v2/home?region={region}#Instances:search={instance_id};sort=instanceId"
            if self.ec2_cache_by_region.get(aws_session.region_name) is None:
                LOG.debug(f"  Caching EC2 instances for region {region}...")
                start = time.time()
                self.ec2_cache_by_region[aws_session.region_name] = []
                for reservation in aws_session.client("ec2").get_paginator("describe_instances").paginate().build_full_result().get("Reservations"):
                    self.ec2_cache_by_region[aws_session.region_name].extend(reservation.get("Instances"))
                LOG.debug(f"  EC2 instances cache loaded in {(time.time() - start):.2f} secs.")
