"""
awsipinventory.discovery module.
"""
from typing import Any, Dict, Optional

from pydantic import BaseModel

from awsipinventory import AwsInterface


class BaseServiceInterface(BaseModel):
    """
    Base class for detected service interfaces.
    """
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


class BaseInterfaceDetector:
    """
    Base class for discovered objects.
    """
    @staticmethod
    def detect(interface_data: Dict[str, Any], interface: BasicInterface) -> Optional[BaseServiceInterface]:
        """
        Abstract method that the child classes must implement and return an object with the corresponding information.
        """
        raise NotImplementedError()
