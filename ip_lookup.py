# Program gets a list of IP address(es) seperated by a space from the command line, and prints the response
# To run program: Type "python ip_lookup.py" in the command line to run 
# To run unit testing: Type "python -m unittest ip_lookup.py" in the command line to run

import requests
import json
import time
import ipaddress
import config
import unittest

print("Lookup information on IP addresses")
print("Enter IP address(es):")

ip_input = input() #Get input runtime arguments from user from the command line 
ip_list = ip_input.split() #Store individual ip addresses in a list

api_calls_count = 0 #GLobal variable to store number of API calls requested

f = open('unit_test_result_check.txt','r') #Read content of unit test expected result file for the valid IP address 125.64.43.7
unit_test_result_check = f.read()

#Unit test cases
class Test_IP(unittest.TestCase):
    #Unit test case for a valid IP address
    def test_valid_IP(self):
        result = call_api_ip_address("125.64.43.7")
        expected = unit_test_result_check
        self.assertEqual(result, expected)
        
    #Unit test case for an invalid IP address    
    def test_invalid_IP(self):
        result = call_api_ip_address("500.20.3.60")
        expected = 0
        self.assertEqual(result, expected)
        
#Sleep for 60 seconds if the limit on number of API requests per minute is reached
def count_api_calls(api_calls):
    if api_calls == 4:
        time.sleep(60)
        global api_calls_count
        api_calls_count = 0

#Function to check validity of IP address
def check_ip_address_validity(ip_address):
    try:
        ip = ipaddress.ip_address(ip_address)
        if ip.version == 4: #Only IPv4 addresses are accepted by the API
            print("\nInformation for IP address:",ip_address)
            return 1
        if ip.version == 6: # Case when the IP address entered is of type IPv6
            print("\nIPv6 IP address:",ip_address,"is not supported by the API")
            return 0
    except ValueError: #Case when the IP address entered is invalid
        print("\n",ip_address,"is not a valid IP address")
        return 0

#Function to make API calls
def call_api_ip_address(ip_address):
    ip_valid_flag = check_ip_address_validity(ip_address)
    
    #Case when IP address is valid
    if ip_valid_flag == 1:
        url = "https://www.virustotal.com/api/v3/ip_addresses/" + ip_address
        headers={'x-apikey' : config.api_key} #Get API key from config.py
        req = requests.get(url, headers=headers)
        global api_calls_count
        api_calls_count += 1
        return json.dumps(req.json(), indent=2) #Return a readable JSON formatted output
    
    #Case when IP address is not valid
    else:
        return 0

for ip in ip_list:
    count_api_calls(api_calls_count) #Check number of API calls made
    api_response = call_api_ip_address(ip) #Check validity of IP address
    if api_response != 0:
        print(api_response) #Print API response as output

f.close()