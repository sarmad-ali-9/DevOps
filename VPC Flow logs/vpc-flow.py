#!/bin/python3

import re
from sys import exit

destination  = {}
subnet_regex = re.compile(r'^192\.168\.[0-9]{1,3}\.[0-9]{1,3}$')

def read_file(file_path):
    '''
    Read and process `vpc-flow logs` file. Populate the `destination` hashmap with the following format:
    Key: Destination IP (Excludes the traffic between NAT Gateway and Private AWS resources)
    Value: Bytes sent to the destination IP
    '''
    try:
        with open(file_path) as vpc_logs:
            logs = vpc_logs.readlines()
            for line in logs:
                dst_address = line.split(' ')[4]
                bytes       = line.split(' ')[9]

                if line.split(' ')[3] == 'srcaddr' or subnet_regex.search(dst_address):
                    continue
                if dst_address not in destination:
                    destination[dst_address] = int(bytes)
                else:
                    destination[dst_address] = destination[dst_address] + int(bytes)
    except Exception as e:
        print("An error ocurred while reading/processing the file.")
        print(e)
        exit(1)

def top_destinations():
    '''
    Process the `destination` hashmap and sort (descending order ) it using `bytes` as the key.
    '''
    try:
        top_destinations = dict(sorted(destination.items(), key=lambda item: item[1], reverse=True))
        range = 1
        for key, value in top_destinations.items():
            if range > 20:
                break
            print(key, value)
            range = range + 1
    except Exception as e:
        print("An error ocurred while finding top 20 IPs.")
        print(e)
        exit(1)

def main():
    read_file("vpc-flow.log")
    print("Top 20 destination IPs sorted by bytes sent (descending order):")
    top_destinations()


if __name__ == '__main__':
    main()
