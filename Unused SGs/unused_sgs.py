import boto3
from sys import exit


try:
    client = boto3.client('ec2')
except Exception as e:
    print("Unable to call AWS API.")
    print(e)
    exit(1)

all_security_groups       = []
all_network_interfaces_sg = []


def get_security_groups():
    '''
    Fetch all security groups.
    '''
    try:
        security_groups = client.describe_security_groups()
        for security_group in security_groups['SecurityGroups']:
            security_group_id          = security_group['GroupId']
            security_group_name        = security_group['GroupName']
            security_group_description = security_group['Description']
            security_group_object = {
                'Security_Group_Id':          security_group_id,
                'Security_Group_Name':        security_group_name,
                'Security_Group_Description': security_group_description
            }
            all_security_groups.append(security_group_object)
    except Exception as e:
        print("An error ocurred while fetching/processing securty groups.")
        print(e)
        exit(1)


def get_network_interfaces():
    '''
    Fetch all security groups associated with network interfaces.
    '''
    global all_network_interfaces_sg
    security_groups        = []
    unique_security_groups = []
    try:
        network_interfaces = client.describe_network_interfaces()
        for network_interface in network_interfaces['NetworkInterfaces']:
            for sg in network_interface['Groups']:
                security_groups.append(sg)

        for sg in security_groups:
            unique_security_groups.append(sg['GroupName'])
        all_network_interfaces_sg = list(set(unique_security_groups))
    except Exception as e:
        print("An error ocurred while fetching/processing network interfaces.")
        print(e)
        exit(1)


def filter_security_groups():
    '''
    Segregate all security groups, which are not associated with a network interface.
    '''
    unused_security_groups = []
    try:
        for sg in all_security_groups:
            if sg['Security_Group_Name'] not in all_network_interfaces_sg:
                unused_security_groups.append(sg)

        return unused_security_groups
    except Exception as e:
        print("An error ocurred while segregating security groups.")
        print(e)
        exit(1)


def main():
    get_security_groups()
    get_network_interfaces()

    unused_security_groups = filter_security_groups()
    for security_group in unused_security_groups:
        print(security_group)


if __name__ == '__main__':
    main()
