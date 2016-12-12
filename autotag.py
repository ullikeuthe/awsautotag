from __future__ import print_function
import json
import boto3, botocore
import logging
import time
import datetime, sys, pprint
from boto3.dynamodb.conditions import Key, Attr
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
            self.resource.load()
            self.type = "NetworkInterface"
            #print(self.resource.tag_set)
        else:
            raise TypeError("unsupported resource type")
            # AttributeError: 'ec2.NetworkInterface' object has no attribute 'tags'


    def _to_tag_dict(self,tags):
        '''
        converts a boto list of tags to a dictionary 
        '''
        tagdict = {}

        for tag in tags:
            tagdict[tag['Key']] = tag['Value']
        return tagdict


    def get_tags(self):
        '''
        returns the instances current tags as a simple dict i.e. {'Name': 'i-54543532', 'owner': 'teddy'}
        '''
        tags = {}
        try:
            tags =  self._to_tag_dict(self.resource.tags)
        except:
            try:
                tags = self._to_tag_dict(self.resource.tag_set)
            except:
                # some resources like network interface do not support .tags
                # a workaround is the use of tag_set
                # see: https://github.com/boto/boto3/issues/628
                pass
        finally:
            return tags
        

    def add_tags(self, new_tags):
        '''
        adds new tags to the resource
        provide new_tags as dict
        '''
        current_tags = self.get_tags()
        # requiredtags = ['ApplicationName','Environment','CostReference','ApplicationID','TicketReference','SecurityContactMail','TechnicalContactMail']

        print("New_Tags: "+str(new_tags))
        print("Cur_Tags: "+str(current_tags))

        for tagname, tagval in new_tags.items():
            if not tagname in current_tags.keys():
                # add new tag
                current_tags[tagname] = tagval
            else:
                # tag already exists -> check value
                logger.warn("%s already has tag %s but current value is %s instead of %s" % (self.id, tagname, current_tags[tagname], tagval))

        # convert to list of tags and update
        new_tags_list = []
        for key,value in current_tags.items():
            new_tags_list.append({ 'Key': key, 'Value': value })

        print(new_tags_list)
        self.save_tags(new_tags_list)


    def save_tags(self, new_tags_list):
        self.resource.create_tags(Tags=new_tags_list)
        
        
class S3TaggableResource(TaggableResource):

    def __init__(self, id):
        self.id = id
        self.type = "S3Bucket"
        self.resource = None
        self.client = boto3.client('s3')


    def get_tags(self):
        '''
        returns the instances current tags as a simple dict i.e. {'Name': 'i-54543532', 'owner': 'teddy'}
        '''
        tags = {}
        try:
            response = self.client.get_bucket_tagging(Bucket=self.id)
            if 'TagSet' in response:
                return self._to_tag_dict(response['TagSet'])
            else:
                return tags
        except:
            return tags


    def save_tags(self, new_tags_list):
        response = self.client.put_bucket_tagging(Bucket=self.id,Tagging={'TagSet': new_tags_list })


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

        #if not self.detail['responseElements']:
        #    raise RuntimeError('Not responseElements found')


class dbdal():

    def __init__(self):
        self.ok = True
        self.default_table = "account_tags"
        self.db = boto3.client('dynamodb')
        self.res = boto3.resource('dynamodb')


    def create_table(self):
        self.res.create_table(TableName=self.default_table,
            KeySchema=[ {'AttributeName': 'AssumedRole', 'KeyType': 'HASH'},
                        {'AttributeName': 'ApplicationName','KeyType': 'RANGE'}],
            AttributeDefinitions=[{'AttributeName': 'ApplicationName', 'AttributeType': 'S'},
                                      {'AttributeName': 'AssumedRole', 'AttributeType': 'S'}],
            ProvisionedThroughput={'ReadCapacityUnits': 5,'WriteCapacityUnits': 5})


    def query(self,key):
        #self.db.quey(TableName=self.default_table, IndexName=assumed_role, Select='ALL_ATTRIBUTES'
        #self.db.query(TableName=self.default_table, IndexName='assumed_role', Select='ALL_ATTRIBUTES')
        table = self.res.Table(self.default_table)
        try:
            response = table.query(KeyConditionExpression=Key('AssumedRole').eq(key))
            return response
        except botocore.exceptions.ClientError as rex:
            if "ResourceNotFoundException" in str(rex):
                # table not found -> create table
                self.create_table()


def lambda_handler(event, context):
    ids = []
    cwe = CloudWatchEvent(event)
    ec2 = boto3.resource('ec2')

    dal = dbdal()
    res = dal.query(cwe.assumedrole)
#    pprint.pprint(res, indent=4)
#    try:
#        if not res['ResponseMetadata']['HTTPStatusCode'] == 200 and res['Count'] == 1:
#            logger.warn(
#    

    if cwe.eventname == 'CreateBucket':
        bucketname = cwe.detail['requestParameters']['bucketName']
        bucket = S3TaggableResource(bucketname)
        tags = bucket.get_tags()
        #pprint.pprint(tags, indent=4)
        bucket.add_tags({'ApplicationName': 'foobar'})

        #tagS3Bucket(bucketname)
        #logger.info(ids)
    elif cwe.eventname == 'CreateVolume':
        ids.append(cwe.detail['responseElements']['volumeId'])
        #logger.info(ids)
    elif cwe.eventname == 'CreateImage':
        ids.append(cwe.detail['responseElements']['imageId'])
        #logger.info(ids)
    elif cwe.eventname == 'CreateSnapshot':
        ids.append(cwe.detail['responseElements']['snapshotId'])
        #logger.info(ids)
    elif cwe.eventname == 'RunInstances':
        items = cwe.detail['responseElements']['instancesSet']['items']
        for item in items:
            ids.append(item['instanceId'])

            xx = TaggableResource(item['instanceId'])
            xx.add_tags({'new_tag': 'new_value'})

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
            print(tr.get_tags())

            #tdict = to_tag_dict(instance.tags)
            #tlist = to_tag_list(tdict)
            #ec2.create_tags(Resources=ids, Tags=[{'Key': 'autotag:owner', 'Value': user}, {'Key': 'autotag:role', 'Value': assumedrole}])

    #logger.info(' Remaining time (ms): ' + str(context.get_remaining_time_in_millis()) + '\n')
    return True




if __name__ == "__main__":
    #with open('ec2run.json') as json_data:
    with open('s3run.json') as json_data:
        d = json.load(json_data)
        json_data.close()
        lambda_handler(d, 'context')    




