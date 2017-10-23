import json
import ipaddress
import boto3

def byteify(input):
    if isinstance(input, dict):
        return {byteify(key): byteify(value)
                for key, value in input.iteritems()}
    elif isinstance(input, list):
        return [byteify(element) for element in input]
    elif isinstance(input, unicode):
        return input.encode('utf-8')
    else:
        return input
    
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

onprem = [
    "192.0.0.0/16",
    "10.218.0.0/16",
    "10.220.0.0/23",
    "172.31.100.0/18",
    ]

#client = boto3.client(
#    'config', 
#    aws_access_key_id='ENTER YOURS HERE', 
#    aws_secret_access_key='ENTER YOURS HERE',
#    )

def handler(event, context):
    config_service = boto3.client('config')
    event_item = json.loads(event['invokingEvent'])
    rules_item = json.loads(event['ruleParameters'])
    config_item = event_item['configurationItem']
    cidr = config_item['configuration']['cidrBlock']
    resource_type = config_item['resourceType']
    
    #print json.dumps(config_item, indent=4)
    #print json.dumps(event_item)
    #print json.dumps(cidr)
    
    if config_item['configurationItemStatus'] == 'ResourceDeleted' or \
       resource_type != 'AWS::EC2::VPC':
        return
    
    evaluation = {
        'ComplianceResourceType': config_item['resourceType'],
        'ComplianceResourceId': config_item['resourceId'],
        'ComplianceType': 'NON_COMPLIANT',
        'OrderingTimestamp': config_item['configurationItemCaptureTime']
    }

    result = cidrcheck(onprem, cidr)
    
    if result is True:
        evaluation['ComplianceType'] = 'COMPLIANT'
    else:
        evaluation['ComplianceType'] = 'NON_COMPLIANT'
    
    config_service.put_evaluations(
       Evaluations=[evaluation], ResultToken=event['resultToken']
    )
    return evaluation['ComplianceType']

    