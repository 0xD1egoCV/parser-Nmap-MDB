import xml.dom.minidom
import argparse
import pymongo

host= 'localhost'
port = '27017'
URI_CONNECTION = "mongodb://" + host + ":" + port +  "/"
database = 'Scan'

def parser_args():
    parser = argparse.ArgumentParser()
    file = parser.add_mutually_exclusive_group(required=False)
    file.add_argument('-f', '--file', type=str, help='Nmap report, XML format')
    parser.add_argument('-g ','--get', help= 'get report from db', action="store_true")
    args = parser.parse_args()
    return args

def conect():
    print("pruebita")
    try:
        global client
        client = pymongo.MongoClient(URI_CONNECTION)
        client.server_info()
        print("Conected", host)
    except pymongo.errors.ConnectionFailure as error:
        print("Failed to Connect")

def get_info(xml_report):
    targets = []
    report = xml_report.getElementsByTagName("host")
    for host in report:
        ports = []
        address = host.getElementsByTagName("address")[0]
        ip = address.getAttribute("addr")
        hostname = host.getElementsByTagName("hostname")[0]
        domain = hostname.getAttribute("name")
        res_ports = host.getElementsByTagName("port")
        for port in res_ports:
            service_name = ''
            service_product = ''
            service_version = ''
            portid = int(port.getAttribute("portid"))
            service = port.getElementsByTagName("service")[0]    
            service_name = service.getAttribute("name")
            service_product = service.getAttribute("product")
            service_version = service.getAttribute("version")
            ports_info = {
                'portid':portid,
                'service_name':service_name,
                'service_product':service_product,
                'service_version':service_version
            }
            ports.append(ports_info)
        target = {
            "hostname":domain,
            "ipAdd":ip,
            "ports":ports
        }
        targets.append(target)
    save_report(targets)

def save_report(targets):
    conect()
    destination = 'Targes'
    collection = client[database][destination]
    for i in targets:
        collection.insert_one(i)
    print('Save successful')

def get_report():
    conect()
    db = client["Scan"]
    coleccion = db["Targes"]
    for targe in coleccion.find():
        print("******************************************************")
        domain = targe["hostname"]
        ip = targe["ipAdd"]
        ports = targe["ports"]
        print("Domain: "+ domain)
        print("IP: "+ip)
        for port in ports:
            print("port: "+ str(port["portid"])+ " service: "+str(port["service_name"])+" version: "+str(port["service_version"]))

if __name__=='__main__':
    args = parser_args()
    repor = args.file
    if args.file:
        xml_report = xml.dom.minidom.parse(repor)
        get_info(xml_report)
    elif args.get :
        get_report()
    else:
        print('Incorrect arguments, -h for help')
