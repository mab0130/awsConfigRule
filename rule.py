# Import libraries - Lambda will require ipaddress to be uploaded

import json
import ipaddress
import boto3

# Edit this list to include all networks that represent "On prem/Datacenter/remote office etc.."
onprem = [
    "192.0.0.0/16",
    "10.218.0.0/16",
    "10.220.0.0/23",
    "172.31.100.0/18",
    ]
# This function uses the ipaddress library to compre the 'onprem' list with AWS Account VPC's  
def cidrcheck(net1, net2):
    prem = map(unicode, net1)   
    test=[]
    for i in prem:
        n1 = ipaddress.IPv4Network(i, strict=False)
        n2 = ipaddress.IPv4Network(net2)
        test.append(n1.overlaps(n2))
    

    if True in test:
        return False
    else:
        return True

# Lambda Function Handler filename.handler - 
# Creates AWS Config Rule connection and parses event object to find VPC CIDR's
def handler(event, context):
    config_service = boto3.client('config')
    event_item = json.loads(event['invokingEvent'])
    rules_item = json.loads(event['ruleParameters'])
    config_item = event_item['configurationItem']
    cidr = config_item['configuration']['cidrBlock']
    resource_type = config_item['resourceType']
    
# Make sure config_item is not deleted and of the correct type    
    if config_item['configurationItemStatus'] == 'ResourceDeleted' or \
       resource_type != 'AWS::EC2::VPC':
        return

# Setup the Evaluation object and set its variables to the event object    
    evaluation = {
        'ComplianceResourceType': config_item['resourceType'],
        'ComplianceResourceId': config_item['resourceId'],
        'ComplianceType': 'NON_COMPLIANT',
        'OrderingTimestamp': config_item['configurationItemCaptureTime']
    }
# Execute evaluation
    result = cidrcheck(onprem, cidr)
    
    if result is True:
        evaluation['ComplianceType'] = 'COMPLIANT'
    else:
        evaluation['ComplianceType'] = 'NON_COMPLIANT'
# Return the evaluation status to the AWS Config Rule service    
    config_service.put_evaluations(
       Evaluations=[evaluation], ResultToken=event['resultToken']
    )
    return evaluation['ComplianceType']

    