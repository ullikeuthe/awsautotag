from __future__ import print_function
import json
import boto3
import logging
import time
import datetime, sys
#from collections import OrderedDict

logging.basicConfig()
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def to_tag_list(tagdict):
    '''
    converts a dict to a boto compatible list of tags dictionary
    '''
    tags = []
    for key,value in tagdict.items():
        tags.append({ key: value })
    return tags

        

class TaggableResource():

    def __init__(self, id):
        self.id = id
        self.tags_supported_types = ['Instance', 'Volume']
        self.type = None
        self.resource = None
        self.client = boto3.resource('ec2')
        if id.startswith('i-'):
            self.resource = self.client.Instance(id) 
            self.type = "Instance"
        elif id.startswith('vol-'):
            self.resource = self.client.Volume(id) 
            self.type = "Volume"
        elif id.startswith('eni-'):
            self.resource = self.client.NetworkInterface(id) 
            self.type = "NetworkInterface"
        else:
            raise TypeError("unsupported resource type")


    def _to_tag_dict(self,tags):
        '''
        converts a boto list of tags to a dictionary 
        '''
        tagdict = {}
        requiredtags = ['ApplicationName','Environment','CostReference','ApplicationID','TicketReference','SecurityContactMail','TechnicalContactMail']
    
        for tag in tags:
            tagdict[tag['Key']] = tag['Value']
    
        for rtag in requiredtags:
            if rtag not in tagdict:
                    tagdict[rtag] = ''
    
        return tagdict


    def get_tags(self):
        if self.type in self.tags_supported_types:
            return self._to_tag_dict(self.resource.tags)
        else:
            return {}
        

    def add_tags(self, new_tags):
        '''
        adds new tags to the resource
        provide new_tags as dict
        '''
        tags = []
        for key,value in new_tags.items():
            tags.append({ key: value })

        current_tags = self.get_tags()
        tags.append(tags)
        print(tags)
        self.resource.create_tags(Tags=tags)
        


class CloudWatchEvent():

    def __init__(self,event):
        self.region = event['region']
        self.detail = event['detail']
        self.eventname = self.detail['eventName']
        self.arn = self.detail['userIdentity']['arn']
        self.principal = self.detail['userIdentity']['principalId']
        self.assumedrole = self.detail['userIdentity']['sessionContext']['sessionIssuer']['userName']
        self.creator = event['detail']['userIdentity']['principalId'].split(':')[1]
        self.userType = self.detail['userIdentity']['type']
        self.user = ''
        if self.userType == 'IAMUser':
            self.user = self.detail['userIdentity']['userName']
        else:
            self.user = self.principal.split(':')[1]

        if not self.detail['responseElements']:
            raise RuntimeError('Not responseElements found')


def lambda_handler(event, context):
    ids = []
    cwe = CloudWatchEvent(event)
    ec2 = boto3.resource('ec2')

    if cwe.eventname == 'CreateVolume':
        ids.append(cwe.detail['responseElements']['volumeId'])
        logger.info(ids)
    elif cwe.eventname == 'CreateImage':
        ids.append(cwe.detail['responseElements']['imageId'])
        logger.info(ids)
    elif cwe.eventname == 'CreateSnapshot':
        ids.append(cwe.detail['responseElements']['snapshotId'])
        logger.info(ids)
    elif cwe.eventname == 'RunInstances':
        items = cwe.detail['responseElements']['instancesSet']['items']
        for item in items:
            ids.append(item['instanceId'])
        base = ec2.instances.filter(InstanceIds=ids)
        for instance in base:
            for vol in instance.volumes.all():
                ids.append(vol.id)
            for eni in instance.network_interfaces:
                ids.append(eni.id)
    else:
        raise RuntimeError('unsupported action')

    # tagging the resources ##############################################################
    if ids:
        for resourceid in ids:
            logger.info('Tagging resource ' + resourceid)
            tr = TaggableResource(resourceid)
            
            #print(tr.get_tags())
            #tr.add_tags({'foo': 'bar'})
            tr.get_tags()

            #tdict = to_tag_dict(instance.tags)
            #tlist = to_tag_list(tdict)
            #ec2.create_tags(Resources=ids, Tags=[{'Key': 'autotag:owner', 'Value': user}, {'Key': 'autotag:role', 'Value': assumedrole}])

    #logger.info(' Remaining time (ms): ' + str(context.get_remaining_time_in_millis()) + '\n')
    return True




if __name__ == "__main__":
    with open('ec2run.json') as json_data:
        d = json.load(json_data)
        json_data.close()
        lambda_handler(d, 'context')    




