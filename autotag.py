from __future__ import print_function
import json
import boto3
import logging
import time
import datetime, sys

logging.basicConfig()

logger = logging.getLogger()
logger.setLevel(logging.INFO)



def to_tag_list(tagdict):
    tags = []
    for key,value in tagdict.items():
        tags.append({ key: value })
    return tags
        
def to_tag_dict(tags):
    tagdict = {}
    requiredtags = ['ApplicationName','Environment','CostReference','ApplicationID','TicketReference','SecurityContactMail','TechnicalContactMail']

    for tag in tags:
        tagdict[tag['Key']] = tag['Value']

    for rtag in requiredtags:
        if rtag not in tagdict:
                tagdict[rtag] = ''

    return tagdict

def lambda_handler(event, context):
    #logger.info('Event: ' + str(event))

    ids = []


    region = event['region']
    detail = event['detail']
    eventname = detail['eventName']
    arn = detail['userIdentity']['arn']
    principal = detail['userIdentity']['principalId']
    assumedrole = detail['userIdentity']['sessionContext']['sessionIssuer']['userName']
    creator = event['detail']['userIdentity']['principalId'].split(':')[1]
    userType = detail['userIdentity']['type']
    user = ''
    
    if userType == 'IAMUser':
        user = detail['userIdentity']['userName']
    else:
        user = principal.split(':')[1]

    logger.info('assumeRole: '+ str(assumedrole))
    logger.info('principalId: ' + str(principal))
    logger.info('region: ' + str(region))
    logger.info('eventName: ' + str(eventname))
#    logger.info('detail: ' + str(detail))

    if not detail['responseElements']:
        logger.warning('Not responseElements found')
        if detail['errorCode']:
            logger.error('errorCode: ' + detail['errorCode'])
        if detail['errorMessage']:
            logger.error('errorMessage: ' + detail['errorMessage'])
        return False

    ec2 = boto3.resource('ec2')

    if eventname == 'CreateVolume':
        ids.append(detail['responseElements']['volumeId'])
        logger.info(ids)

    elif eventname == 'RunInstances':
        items = detail['responseElements']['instancesSet']['items']
        for item in items:
            ids.append(item['instanceId'])

        logger.info('+++++++++++++++++++++++++'+str(ids))
        logger.info('number of instances: ' + str(len(ids)))

        base = ec2.instances.filter(InstanceIds=ids)

        #loop through the instances
        logger.info('loop through the instances')
        for instance in base:

            print('Tags: ')
            tdict = to_tag_dict(instance.tags)
            print(str(tdict))
            tlist = to_tag_list(tdict)
            print(str(tlist))


            logger.info('  '+str(instance))
            for vol in instance.volumes.all():
                ids.append(vol.id)
            for eni in instance.network_interfaces:
                ids.append(eni.id)

    elif eventname == 'CreateImage':
        ids.append(detail['responseElements']['imageId'])
        logger.info(ids)

    elif eventname == 'CreateSnapshot':
        ids.append(detail['responseElements']['snapshotId'])
        logger.info(ids)
    else:
        logger.warning('Not supported action')

    if ids:
        for resourceid in ids:
            logger.info('Tagging resource ' + resourceid)
            ec2.create_tags(Resources=ids, Tags=[{'Key': 'autotag:owner', 'Value': user}, {'Key': 'autotag:role', 'Value': assumedrole}])


    logger.info(' Remaining time (ms): ' + str(context.get_remaining_time_in_millis()) + '\n')
    return True




if __name__ == "__main__":
    with open('ec2run.json') as json_data:
        d = json.load(json_data)
        json_data.close()

        lambda_handler(d, 'context')    




