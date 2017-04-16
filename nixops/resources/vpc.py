# -*- coding: utf-8 -*-

# Automatic provisioning of AWS VPCs.

import boto3
import nixops.util
import nixops.resources
import nixops.ec2_utils

class VPCDefinition(nixops.resources.ResourceDefinition):
    """Definition of a VPC."""

    @classmethod
    def get_type(cls):
        return "vpc"

    @classmethod
    def get_resource_type(cls):
        return "vpc"

    def show_type(self):
        return "{0}".format(self.get_type())


class VPCState(nixops.resources.ResourceState):
    """State of a VPC."""

    state = nixops.util.attr_property("state", nixops.resources.ResourceState.MISSING, int)
    vpc_id = nixops.util.attr_property("ec2.vpcId",None)
    access_key_id = nixops.util.attr_property("ec2.accessKeyId", None)
    region = nixops.util.attr_property("region", None)
    cidr_block = nixops.util.attr_property("ec2.vpcCidrBlock", None)

    @classmethod
    def get_type(cls):
        return "vpc"

    def __init__(self, depl, name, id):
        nixops.resources.ResourceState.__init__(self, depl, name, id)
        self._client = None

    def show_type(self):
        s = super(VPCState, self).show_type()
        if self.region: s = "{0} [{1}]".format(s, self.region)
        return s

    @property
    def resource_id(self):
        return self.vpc_id

    def prefix_definition(self, attr):
        return {('resources', 'vpc'): attr}

    def get_physical_spec(self):
        return {}

    def get_definition_prefix(self):
        return "resources.vpc."

    def connect(self):
        if self._client: return
        assert self.region
        (access_key_id, secret_access_key) = nixops.ec2_utils.fetch_aws_secret_key(self.access_key_id)
        self._client = boto3.client('ec2', region_name=self.region, aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key)

    def _destroy(self):
        if self.state != self.UP: return
        self.connect()
        self.log("destroying VPC {0}...".format(self.vpc_id))
        self._client.delete_vpc(VpcId=self.vpc_id)
        with self.depl._db:
            self.state = self.MISSING
            self.vpc_id = None
            self.region = None
            self.cidr_block = None
            self.instance_tenancy = None

    def create(self, defn, check, allow_reboot, allow_recreate):
        self.access_key_id = defn.config['accessKeyId'] or nixops.ec2_utils.get_access_key_id()
        if not self.access_key_id:
            raise Exception("please set 'accessKeyId', $EC2_ACCESS_KEY or $AWS_ACCESS_KEY_ID")

        if self.state == self.UP and (self.cidr_block != defn.config['cidr_block'] or self.region != defn.config['region']):
            self.warn("vpc definition changed, recreating...")
            self._destroy()
            self._client = None

        self.region = defn.config['region']

        self.connect()

        vpc_id = self.vpc_id

        if self.state != self.UP:
            self.log("creating vpc under region {0}".format(defn.config['region']))
            vpc = self._client.create_vpc(CidrBlock=defn.config['cidrBlock'], InstanceTenancy=defn.config['instanceTenancy'])
            print vpc
            vpc_id = vpc.VpcId

        if defn.config['enableClassicLink']:
            self.log("enabling vpc classic link")
            self._client.enable_vpc_classic_link(VpcId=vpc_id)

        self._client.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport=defn.config['enableDnsSupport'],
                    enableDnsHostnames=defn.config['enableDnsHostnames'])

        if defn.config['enableClassicLink']:
            self._client.enable_vpc_classic_link(VpcId=vpc_id)
        else:
            self._client.disable_vpc_classic_link(VpcId=vpc_id)

        def tag_updater(tags):
            self._client.create_tags(VpcId=vpc_id, Tags=[{"Key": k, "Value": tags[k]} for k in tags])

        self.update_tags_using(tag_updater, user_tags=defn.config["tags"], check=check)

        with self.depl._db:
           self.state = self.UP
           self.vpc_id = vpc_id
           self.region = defn.config['region']
           self.cidr_block = defn.config['cidrBlock']
           self.instance_tenancy = defn.config['instanceTenancy']

    def destroy(self, wipe=False):
        self._destroy()
        return True
