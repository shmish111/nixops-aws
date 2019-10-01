# -*- coding: utf-8 -*-

# Automatic provisioning of EC2 key pairs.

import tempfile
import os
import subprocess
import nixops.util
import nixops.resources
import nixopsaws.ec2_utils


class EC2KeyPairDefinition(nixops.resources.ResourceDefinition):
    """Definition of an EC2 key pair."""

    @classmethod
    def get_type(cls):
        return "ec2-keypair"

    @classmethod
    def get_resource_type(cls):
        return "ec2KeyPairs"

    def __init__(self, xml):
        nixops.resources.ResourceDefinition.__init__(self, xml)
        self.keypair_name = xml.find("attrs/attr[@name='name']/string").get("value")
        self.region = xml.find("attrs/attr[@name='region']/string").get("value")
        self.access_key_id = xml.find("attrs/attr[@name='accessKeyId']/string").get("value")

    def show_type(self):
        return "{0} [{1}]".format(self.get_type(), self.region)


class EC2KeyPairState(nixops.resources.ResourceState):
    """State of an EC2 key pair."""

    state = nixops.util.attr_property("state", nixops.resources.ResourceState.MISSING, int)
    keypair_name = nixops.util.attr_property("ec2.keyPairName", None)
    public_key = nixops.util.attr_property("publicKey", None)
    private_key = nixops.util.attr_property("privateKey", None)
    access_key_id = nixops.util.attr_property("ec2.accessKeyId", None)
    region = nixops.util.attr_property("ec2.region", None)


    @classmethod
    def get_type(cls):
        return "ec2-keypair"


    def __init__(self, depl, name, id):
        nixops.resources.ResourceState.__init__(self, depl, name, id)
        self._session = None
        self._client = None


    def show_type(self):
        s = super(EC2KeyPairState, self).show_type()
        if self.region: s = "{0} [{1}]".format(s, self.region)
        return s


    @property
    def resource_id(self):
        return self.keypair_name


    def get_definition_prefix(self):
        return "resources.ec2KeyPairs."


    def _connect(self):
        if self._client: return
        self._session = nixopsaws.ec2_utils.connect(self.region, self.access_key_id)
        self._client = self._session.client('ec2')


    def create(self, defn, check, allow_reboot, allow_recreate):

        self.region = defn.region
        self._connect()

        # Generate the key pair
        if not self.public_key:
            self.log("generate key pair %s" % defn.keypair_name)
            response = self._client.create_key_pair(KeyName=defn.keypair_name,DryRun=False)
            private_key = response["KeyMaterial"]
            temp = tempfile.NamedTemporaryFile(mode='w+t',delete=False)
            temp.writelines(private_key)
            temp.close()
            public_key = subprocess.check_output(["ssh-keygen", "-y", "-f", temp.name],stderr=subprocess.STDOUT)
            os.remove(temp.name)
            self.log("generated key pair")
            with self.depl._db:
                self.keypair_name = response["KeyName"]
                self.public_key = public_key
                self.private_key = private_key

        if check or self.state != self.UP:
            kp = self._client.describe_key_pairs(KeyNames=[defn.keypair_name])["KeyPairs"][0]["KeyName"]
            self.log("found keypair {0}".format(kp))

            with self.depl._db:
                self.state = self.UP
                self.keypair_name = defn.keypair_name


    def destroy(self, wipe=False):
        def keypair_used():
            for m in self.depl.active_resources.itervalues():
                if isinstance(m, nixopsaws.backends.ec2.EC2State) and m.key_pair == self.keypair_name:
                    return m
            return None

        m = keypair_used()
        if m:
            raise Exception("keypair ‘{0}’ is still in use by ‘{1}’ ({2})".format(self.keypair_name, m.name, m.vm_id))

        if not self.depl.logger.confirm("are you sure you want to destroy keypair ‘{0}’?".format(self.keypair_name)):
            return False

        if self.state == self.UP:
            self.log("deleting EC2 key pair ‘{0}’...".format(self.keypair_name))
            self._connect()
            self._client.delete_key_pair(KeyName=self.keypair_name)

        return True

    def check(self):
        self._connect()
        try:
            kp = self._client.get_key_pair(self.keypair_name)
        except IndexError as e:
            kp = None
        if kp is None:
            self.state = self.MISSING
