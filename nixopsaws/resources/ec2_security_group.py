# -*- coding: utf-8 -*-

# Automatic provisioning of EC2 security groups.

import nixops.resources
import nixops.util
import nixopsaws.ec2_utils
import ipaddress
import boto3
from botocore.exceptions import ClientError

class EC2SecurityGroupDefinition(nixops.resources.ResourceDefinition):
    """Definition of an EC2 security group."""

    @classmethod
    def get_type(cls):
        return "ec2-security-group"

    @classmethod
    def get_resource_type(cls):
        return "ec2SecurityGroups"

    def __init__(self, xml):
        super(EC2SecurityGroupDefinition, self).__init__(xml)
        self.security_group_name = xml.find("attrs/attr[@name='name']/string").get("value")
        self.security_group_description = xml.find("attrs/attr[@name='description']/string").get("value")
        self.region = xml.find("attrs/attr[@name='region']/string").get("value")
        self.access_key_id = xml.find("attrs/attr[@name='accessKeyId']/string").get("value")
        self._session = None
        self._client = None

        self.vpc_id = None
        if not xml.find("attrs/attr[@name='vpcId']/string") is None:
            self.vpc_id = xml.find("attrs/attr[@name='vpcId']/string").get("value")

        self.security_group_rules = []
        for rule_xml in xml.findall("attrs/attr[@name='rules']/list/attrs"):
            ip_protocol = rule_xml.find("attr[@name='protocol']/string").get("value")
            if ip_protocol == "icmp":
                from_port = int(rule_xml.find("attr[@name='typeNumber']/int").get("value"))
                to_port = int(rule_xml.find("attr[@name='codeNumber']/int").get("value"))
            else:
                from_port = int(rule_xml.find("attr[@name='fromPort']/int").get("value"))
                to_port = int(rule_xml.find("attr[@name='toPort']/int").get("value"))
            cidr_ip_xml = rule_xml.find("attr[@name='sourceIp']/string")
            if not cidr_ip_xml is None:
                self.security_group_rules.append([ ip_protocol, from_port, to_port, cidr_ip_xml.get("value") ])
            else:
                group_name = rule_xml.find("attr[@name='sourceGroup']/attrs/attr[@name='groupName']/string").get("value")
                owner_id = rule_xml.find("attr[@name='sourceGroup']/attrs/attr[@name='ownerId']/string").get("value")
                self.security_group_rules.append([ ip_protocol, from_port, to_port, group_name, owner_id ])


    def show_type(self):
        return "{0} [{1}]".format(self.get_type(), self.region)

class EC2SecurityGroupState(nixops.resources.ResourceState):
    """State of an EC2 security group."""

    region = nixops.util.attr_property("ec2.region", None)
    security_group_id = nixops.util.attr_property("ec2.securityGroupId", None)
    security_group_name = nixops.util.attr_property("ec2.securityGroupName", None)
    security_group_description = nixops.util.attr_property("ec2.securityGroupDescription", None)
    security_group_rules = nixops.util.attr_property("ec2.securityGroupRules", [], 'json')
    old_security_groups = nixops.util.attr_property("ec2.oldSecurityGroups", [], 'json')
    access_key_id = nixops.util.attr_property("ec2.accessKeyId", None)
    vpc_id = nixops.util.attr_property("ec2.vpcId", None)

    @classmethod
    def get_type(cls):
        return "ec2-security-group"

    def __init__(self, depl, name, id):
        super(EC2SecurityGroupState, self).__init__(depl, name, id)
        self._session = None
        self._client = None

    def show_type(self):
        s = super(EC2SecurityGroupState, self).show_type()
        if self.region: s = "{0} [{1}]".format(s, self.region)
        return s

    def prefix_definition(self, attr):
        return {('resources', 'ec2SecurityGroups'): attr}

    def get_physical_spec(self):
        return {'groupId': self.security_group_id}

    @property
    def resource_id(self):
        return self.security_group_name

    def create_after(self, resources, defn):
        #!!! TODO: Handle dependencies between security groups
        return {r for r in resources if
                isinstance(r, nixopsaws.resources.vpc.VPCState) or
                isinstance(r, nixopsaws.resources.elastic_ip.ElasticIPState)
               }

    def _connect(self):
        if self._session: return
        assert self.region
        self._session = nixopsaws.ec2_utils.connect(self.region, self.access_key_id)
        self._client = self._session.client('ec2')

    def create(self, defn, check, allow_reboot, allow_recreate):
        def retry_notfound(f):
            nixopsaws.ec2_utils.retry(f, error_codes=['InvalidGroup.NotFound'])

        # Name or region change means a completely new security group
        if self.security_group_name and (defn.security_group_name != self.security_group_name or defn.region != self.region):
            with self.depl._db:
                self.state = self.UNKNOWN
                self.old_security_groups = self.old_security_groups + [{'name': self.security_group_name, 'region': self.region}]

        if defn.vpc_id is not None:
            if defn.vpc_id.startswith("res-"):
                res = self.depl.get_typed_resource(defn.vpc_id[4:].split(".")[0], "vpc")
                defn.vpc_id = res._state['vpcId']

        with self.depl._db:
            self.region = defn.region
            self.security_group_name = defn.security_group_name
            self.security_group_description = defn.security_group_description
            self.vpc_id = defn.vpc_id

        grp = None
        if check:
            with self.depl._db:
                self._connect()

                try:
                    if self.vpc_id:
                        grp = self._client.describe_security_groups(GroupIds=[ self.security_group_id ])["SecurityGroups"][0]
                    else:
                        grp = self._client.describe_security_groups(GroupNames=[defn.security_group_name ])["SecurityGroups"][0]
                    self.state = self.UP
                    self.security_group_id = grp["GroupId"]
                    self.security_group_description = grp["Description"]
                    rules = []
                    for rule in grp["IpPermissions"]:
                        for ipRange in rule["IpRanges"]:
                            new_rule = [ rule["IpProtocol"], rule["FromPort"], rule["ToPort"] ]
                            try:
                                ipaddress.ip_address(ipRange["CidrIp"])
                                new_rule.append(ipRange["CidrIp"])
                            except ValueError:
                                # "CidrIp" value is weirdly either a CIDR range or group ID IIUC
                                # https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_IpRange.html
                                inner_group = self._client.describe_security_groups(GroupIds=[ ipRange["CidrIp"] ])["SecurityGroups"][0]["GroupId"]
                                new_rule.append(inner_group)
                                new_rule.append(rule["OwnerId"])
                            rules.append(new_rule)
                    self.security_group_rules = rules
                except ClientError as e:
                    if e.response['Error']['Code'] != 'InvalidGroup.NotFound':
                        self.state = self.MISSING
                    else:
                        raise

        # Dereference elastic IP if used for the source ip
        resolved_security_group_rules = []
        for rule in defn.security_group_rules:
            if rule[-1].startswith("res-"):
                res = self.depl.get_typed_resource(rule[-1][4:], "elastic-ip")
                rule[-1] = res.public_ipv4 + '/32'
            resolved_security_group_rules.append(rule)

        security_group_was_created = False
        if self.state == self.MISSING or self.state == self.UNKNOWN:
            self._connect()
            try:
                self.logger.log("creating EC2 security group ‘{0}’...".format(self.security_group_name))
                grp = self._client.create_security_group(
                    GroupName=self.security_group_name,
                    Description=self.security_group_description,
                    VpcId=defn.vpc_id
                    )
                self.security_group_id = grp["GroupId"]
                # If group creation succeeded, the group wasn't there before,
                # in which case also its rules must be (re-)created below.
                security_group_was_created = True
            except ClientError as e:
                if self.state != self.UNKNOWN or e.response['Error']['Code'] != 'InvalidGroup.Duplicate':
                    raise
            self.state = self.STARTING #ugh

        new_rules = set()
        old_rules = set()
        if not security_group_was_created:  # old_rules stays {}
            for rule in self.security_group_rules:
                old_rules.add(tuple(rule))
        for rule in resolved_security_group_rules:
            tupled_rule = tuple(rule)
            if not tupled_rule in old_rules:
                new_rules.add(tupled_rule)
            else:
                old_rules.remove(tupled_rule)

        if new_rules:
            self.logger.log("adding new rules to EC2 security group ‘{0}’...".format(self.security_group_name))
            if grp is None:
                self._connect()
                grp = self.get_security_group()
            for rule in new_rules:
                try:
                    if len(rule) == 4:
                        retry_notfound(lambda: self._client.authorize_security_group_ingress(
                            CidrIp=rule[3],
                            FromPort=rule[1],
                            GroupId=grp["GroupId"],
                            ToPort=rule[2],
                            IpProtocol=rule[0]
                        ))
                    else:
                        src_group = self._client.describe_security_groups(GroupIds=[rule[3]])["SecurityGroups"][0]
                        retry_notfound(lambda: self._client.authorize_security_group_ingress(
                            FromPort=rule[1],
                            GroupId=grp["GroupId"],
                            ToPort=rule[2],
                            IpProtocol=rule[0],
                            SourceSecurityGroupName=src_group["GroupName"]
                        ))
                except ClientError as e:
                    if e.response['Error']['Code'] != 'InvalidGroup.Duplicate':
                        raise

        if old_rules:
            self.logger.log("removing old rules from EC2 security group ‘{0}’...".format(self.security_group_name))
            if grp is None:
                self._connect()
                grp = self.get_security_group()
            for rule in old_rules:
                if len(rule) == 4:
                    self._client.revoke_security_group_ingress(
                        CidrIp=rule[3],
                        FromPort=rule[1],
                        GroupId=grp["GroupId"],
                        ToPort=rule[2],
                        IpProtocol=rule[0]
                    )
                else:
                    src_group = self._client.describe_security_groups(GroupIds=[rule[3]])["SecurityGroups"][0]
                    self._client.revoke_security_group_ingress(
                        FromPort=rule[1],
                        GroupId=grp["GroupId"],
                        ToPort=rule[2],
                        IpProtocol=rule[0],
                        SourceSecurityGroupName=src_group["GroupName"]
                    )
        self.security_group_rules = resolved_security_group_rules

        self.state = self.UP

    def get_security_group(self):
        self._connect()
        if self.vpc_id:
            return self._client.describe_security_groups(GroupIds=[ self.security_group_id ])["SecurityGroups"][0]
        else:
            return self._client.describe_security_groups(GroupNames=[ self.security_group_name ])["SecurityGroups"][0]

    def after_activation(self, defn):
        original_region = self.region
        for group in self.old_security_groups:
            if group['region'] != original_region:
                self.region = group['region']
            try:
                self._connect()
                current_group = self._client.describe_security_groups(Filters=[{'Name': 'group-name', 'Values': [group["name"]]}])["SecurityGroups"][0]
                self._client.delete_security_group(GroupId=current_group['Id'])
            except ClientError as e:
                if e.response['Error']['Code'] != 'InvalidGroup.NotFound':
                    raise
            finally:
                self.region = original_region
        self.old_security_groups = []

    def destroy(self, wipe=False):
        if self.state == self.UP or self.state == self.STARTING:
            self.logger.log("deleting EC2 security group `{0}' ID `{1}'...".format(
                self.security_group_name, self.security_group_id))
            self._connect()
            try:
                nixopsaws.ec2_utils.retry(
                    lambda: self._client.delete_security_group(GroupId=self.security_group_id),
                    error_codes=['DependencyViolation'])
            except ClientError as e:
                if e.response['Error']['Code'] != 'InvalidGroup.NotFound':
                    raise

            self.state = self.MISSING
        return True
