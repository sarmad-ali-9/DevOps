## Imports ##
import boto3
import time
import logging
import csv

from sys import exit
from botocore.exceptions import ClientError
from argparse import ArgumentParser, RawTextHelpFormatter


## Global Variables ##
DESCRIPTION = None
ts = time.gmtime()
OUTPUT_FILE = 'ec2_instances' + time.strftime("%Y-%m-%d_%H.%M.%S", ts) + '.csv'


def fetch_instances():
    logging.info("Getting list of EC2 instances ...")
    try:
        ec2_instance_client = boto3.client('ec2')
        instances = ec2_instance_client.describe_instances()
        for res in instances['Reservations']:
            for instance in res['Instances']:
                instance_id = instance['InstanceId']
                private_ip = instance['PrivateIpAddress']
                public_ip = instance['PublicIpAddress']
                for tag in instance['Tags']:
                    if tag['Key'] == 'Name':
                        instance_name = tag['Value']
                if instance_name:
                    logging.info("Name of the EC2 Instance: {}".format(instance_name))
                else:
                   instance_name = 'null'
                logging.info("ID of the EC2 Instance: {}".format(instance_id))
                logging.info("Public IP of the EC2 Instance: {}".format(public_ip))
                logging.info("Private IP of the EC2 Instance: {}".format(private_ip))
                for security_groups in instance['SecurityGroups']:
                    security_group_name = security_groups['GroupName']
                    logging.info("Security Group(s) associated with instance {}: {}".format(instance_id, security_groups['GroupName']))
                    if DESCRIPTION == 'detailed':
                        security_group_id = security_groups['GroupId']
                        fetch_security_groups(ec2_instance_client, security_group_name, security_group_id, instance_id, private_ip, instance_name)
    except ClientError as ce:
        logging.error("An error ocurred while fetching EC2 instances")
        logging.error(ce)
        exit(1)
    except Exception as e:
        logging.error(e)
        exit(1)


def fetch_security_groups(ec2_instance_client, security_group_name, security_group_id, instance_id, private_ip, instance_name='null'):
    logging.info("Getting data for Security Group: {}".format(security_group_name))
    try:
        security_group = ec2_instance_client.describe_security_groups(GroupIds=[security_group_id])
        try:
            with open(OUTPUT_FILE, 'w') as csvfile:
                field_Names = ['instance_id', 'instance_name', 'private_ip', 'security_group_id', 'security_group_name', 'from_port', 'to_port', 'cidr_ip']
                for sec_grp in security_group['SecurityGroups']:
                    for s_g in sec_grp['IpPermissions']:
                        if 'FromPort' in s_g.keys():
                            from_port = s_g['FromPort']
                        else:
                            from_port = 'null'
                        if 'ToPort' in s_g.keys():
                            to_port = s_g['ToPort']
                        else:
                            to_port = 'null'
                        for iprange in s_g['IpRanges']:
                            cidr_ip = iprange['CidrIp']
                            csvWriter = csv.writer(csvfile, delimiter=',')
                            csvWriter.writerow([instance_id, instance_name, private_ip, security_group_id, security_group_name, from_port,to_port,cidr_ip])
        except Exception as e:
            logging.error("Unable to write to {}".format(OUTPUT_FILE))
            logging.error(e)
            exit(1)
    except ClientError as ce:
        logging.error("An error ocurred while getting data for security group {}".format(security_group_id))
        logging.error(ce)
        exit(1)
    except Exception as e:
        logging.error(e)
        exit(1)


def parameters_handler():
    global DESCRIPTION
    parser = ArgumentParser(description='The script list the EC2 Instances with their associated Security Groups.\n\n'
                                        'Script Usage:\n\n'
                                        '\tpython3 list_ec2.py --detailed or python3 list_ec2.py -d\n'
                                        '\t\tOR\n'
                                        '\tpython3 list_ec2.py --brief or python3 list_ec2.py -b\n'
                                        ,formatter_class=RawTextHelpFormatter)
    parser.add_argument('-d', '--detailed', action='store_true', help='Detailed description of the Security Groups')
    parser.add_argument('-b', '--brief', action='store_true', help='Brief description of the Security Groups')
    parser.add_argument('--log', required=False, help='logging level, default is info', default='INFO')

    args = parser.parse_args()

    if args.log:
        if args.log in ['debug', 'DEBUG']:
            logging_level = logging.DEBUG
        elif args.log in ['info', 'INFO']:
            logging_level = logging.INFO
        elif args.log in ['error', 'ERROR']:
            logging_level = logging.ERROR
        elif args.log in ['critical', 'CRITICAL']:
            logging_level = logging.CRITICAL

    if args.detailed:
        DESCRIPTION = 'detailed'

    if args.brief:
        DESCRIPTION = 'brief'

    if args.detailed and args.brief:
        print("Select either detailed (shortform: d) or brief (shortform: b).")
        print("Example:")
        print("\tpython3 list_ec2.py --detailed or python3 list_ec2.py -d")
        print("\t\tOR")
        print("\tpython3 list_ec2.py --brief or python3 list_ec2.py -b\n")
        print("Defaulting to brief ...")
        DESCRIPTION = 'brief'



    logging.basicConfig(format='%(asctime)s: %(levelname)s: %(message)s', datefmt='%d-%b-%y %H:%M:%S', level=logging_level)


def main():
    parameters_handler()
    fetch_instances()


if __name__ == '__main__':
    main()

