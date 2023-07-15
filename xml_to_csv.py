from xml.etree import ElementTree
import csv
import argparse

parser = argparse.ArgumentParser(description="Parse arguments for xml_to_csv converter", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("-xml", help="xml file to convert")
parser.add_argument("-o", "--output", help="csv file to create")
parser.add_argument("--headers", help="The list of csv field headers: insert the headers separated by a comma. (ex. 'h1,h2,h3,h4')")

args = parser.parse_args()
config = vars(args)

xml_file = config['xml']
csv_file = config['output']
headers = config['headers']

# open xml file
tree = ElementTree.parse(xml_file)

# open csv file
output_file = open(csv_file, 'w', newline='', encoding='utf-8')
csvwriter = csv.writer(output_file)

# create the list of columns
headers_list = headers.split(",")
print(headers_list)

# write the headers row
csvwriter.writerow(headers_list)

# Begin writing 
root = tree.getroot()
for eventData in root.findall('ProcessItem'):
    event_data = []

    if 'pid' in headers_list:
        event_pid = eventData.find('pid')
        if event_pid != None:
            event_pid = event_pid.text
        event_data.append(event_pid)
    if 'parentpid' in headers_list:
        event_parentpid = eventData.find('parentpid')
        if event_parentpid != None:
            event_parentpid = event_parentpid.text
        event_data.append(event_parentpid)
    if 'name' in headers_list:
        event_name = eventData.find('name')
        if event_name != None:
            event_name = event_name.text
        event_data.append(event_name)
    if 'arguments' in headers_list:
        event_arguments = eventData.find('arguments')
        if event_arguments != None:
            event_arguments = event_arguments.text
        event_data.append(event_arguments)
    if 'Username' in headers_list:
        event_username = eventData.find('Username')
        if event_username != None:
            event_username = event_username.text
        event_data.append(event_username)
    
    #write the row in csv file
    csvwriter.writerow(event_data)

output_file.close()
    