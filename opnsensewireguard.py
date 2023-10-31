# This script assumes that you've already created the wireguard server under the "Local" tab in the gui.
# make a note of the instance number for that server, you'll need it below.

import uuid # UUID Generation
import shutil # file stuff
import ipaddress # IP address math
import subprocess # launch shell processes
import xml.etree.ElementTree as ET # xml parser.
from collections import defaultdict # action menus.

# Things you can change:
default_endpoint = "server.address.com"
default_client = "client{}" # Will replace {} with the peer number.
default_dns = "192.168.0.1" # either the router or whatever internal dns you have running.
default_network = "192.168.0.0/24" # whatever the network range is for the lan/vlan you want to connect to.
default_instance = "0" # if you have multiple wireguard instances (for example a site-to-site and a roadwarrior), put the roadwarrior instance number here.

# other options - interactive mode or not.
# If you set these to false, the defaults above are used without prompting.
user_prompts = True # enable interactive mode (Strongly recommended unless you're familiar with the script)
package_prompt = True # for interactive mode, prompt to install packages if they're not detected
display_qr = True # for interactive mode, show QR code on screen (always generates png file)

# Things you might change, but probably shouldn't
opnsense_config_xml = "/conf/config.xml"

# A note about the PKG files. If there's a major distro upgrade of FreeBSD (like 14 or higher)
# these package links will break. If that happens, go to
# https://pkg.freebsd.org/
# in a browser and drill down to the correct server package set (in the case below this would be)
# https://pkg.freebsd.org/FreeBSD:13:amd64/quarterly/
# If you attempt to open the All package, you'll get a 404, and that's normal.
# What you need to do is open the packagesite.txz file
# and get into the packagesite.yaml file using a text editor.
# search for {"name":"png" and somewhere down that line there will be a "repopath":"All/png-1.6.37_1.pkg"
# you add that to the package set above to get a url that looks like the links below.
# then, search for {"name":"libqrencode" and grab the "repopath":"All/libqrencode-4.1.1.pkg" 
# These are correct as of 23.7.7
PNG_PKG = "https://pkg.freebsd.org/FreeBSD:13:amd64/release_2/All/png-1.6.39.pkg"
QR_PKG = "https://pkg.freebsd.org/FreeBSD:13:amd64/release_2/All/libqrencode-4.1.1.pkg"

# Don't change anything after this.

def main():
    print("OPNsense wireguard config script")
    print("---------------------------------------------------------------------\n\n")
    
    can_qr = False
    
    if package_prompt:
        print("First off, in order to display a qrcode at the end of the process, ")
        print("we'll need some unsupported packages that I have not vetted fully.")
        print("They've worked fine for me since OPNsense 21.7.x-amd64. Should I install")
        print("these libraries? You can't blame me if this breaks your appliance.\n")
        print("(y) Attempt to install packages")
        print("(n) Skip packages, handle the config yourself")
        print("(q) Quit the program without doing anything")
        add_pkg = input("(y/n/q): ")

        
        action = parse_actions(add_pkg, {'y': install_packages, 'q': user_quit})
        if action is not None:
            can_qr = action()
    else:
        can_qr = install_packages()
        
    try:
        print("Reading config.xml...", end='')
        with open(opnsense_config_xml, "rb") as opnsense_config:
            config_xml = opnsense_config.read()

        print("Successful!")
    except FileNotFoundError:
        print("Failed. Can't find the file?")
        exit(-1)
    except:
        print("Failed. Unknown issue with config file.")
        exit(-1)

    try:
        print("Attempting to parse the config...", end='')
        tree = ET.ElementTree(ET.fromstring(config_xml))
    except ParseError:
        print("Failed. Can't parse config file XML")
        exit(-1)
    except:
        print("Failed. Unknown issue with parser.")
        exit(-1)

    root = tree.getroot()
    print("Getting wireguard instances...", end='')
    servers = root.findall("./OPNsense/wireguard/server/servers/")
    servers_count = len(servers)
    if servers_count == 0:
        print("Could not find any server instances.")
        exit(-1)

    print(f"Found {servers_count}:")
    #servers_count -= 1

    for server in servers:
        name = server.find('name').text
        instance = server.find('instance').text
        print(f"{name}: {instance}")

    if user_prompts:
        print("\nWhich instance number do you want to add a client to?")
        this_instance = input(f"0 to {servers_count}, (blank defaults to ({default_instance})): ") or default_instance
    else:
        this_instance = default_instance

    if (this_instance is None or # Blank
            this_instance == "" or # Empty
            this_instance.lower() != this_instance.upper() or # Non numeric
            int(this_instance) > servers_count): # too high.
        user_quit()

    print(f"You selected {this_instance}. Let me load that server...", end='')
    server = root.findall("./OPNsense/wireguard/server/servers/*[instance='{0}']".format(this_instance))[0]

    if server is None:
        print("\nUnable to load instance {this_instance} from config. Sorry.")
        exit(-1)

    print("Got it!")

    print("Parsing server config for instance...", end='')
    server_conf, client_conf = parse_server_details(server)
    print("Done!")

    print("Parsing client config for instance...", end='')
    client_count = 0
    for client in root.findall("./OPNsense/wireguard/client/clients/"): # get clients
        if client.get("uuid") in server_conf['peers']: # if they're a peer for the server
            client_count += 1
            try:
                used_client_ip = ipaddress.ip_network(client.findtext("tunneladdress")).network_address
                client_conf['net_range'].remove(used_client_ip)
            except:
                print("Failed...")
                exit(-1)
        

    # and now we have a clean ip range with no duplicates!
    safe_ip = str(client_conf['net_range'][0])
    client_conf['tunneladdress'] = f"{safe_ip}/32"
    client_conf['uuid'] = str(uuid.uuid4())
    print("Done!")

    print("Attempting to generate keys...", end='')
    try:
        client_conf['privkey'] = subprocess.check_output('wg genkey', shell=True, encoding="utf-8").rstrip("\n")
        client_conf['pubkey'] = subprocess.check_output("echo {0} | wg pubkey".format(client_conf['privkey']), shell=True, encoding="utf-8").rstrip("\n")
        shared_key = subprocess.check_output('wg genpsk', shell=True, encoding="utf-8").rstrip("\n")
        client_conf['psk'] = shared_key
        server_conf['psk'] = shared_key
    except:
        print("failed!")
        exit(-1)

    print("Successful!")

    if user_prompts:
        print("What server endpoint will this client use?")
        endpoint = input(f"blank defaults to ({default_endpoint}): ") or default_endpoint
    else:
        endpoint = default_endpoint
        
    print(f"Ok, going with ({endpoint})\n")

    server_conf['endpoint'] = f"{endpoint}:{server_conf['port']}"

    if user_prompts:
        print("What dns server will this client use?")
        dns = input(f"blank defaults to ({default_dns}): ") or default_dns
    else:
        dns = default_dns
        
    print(f"Ok, going with ({dns})\n")

    client_conf['dns'] = dns

    generated_client_name = default_client.format(client_count)
    
    if user_prompts:
        print("What name should we assign to this client?")
        client_name = input(f"blank defaults to ({generated_client_name}): ") or generated_client_name
    else:
        client_name = generated_client_name
        
    print(f"Ok, going with ({client_name})\n")

    client_conf['name'] = client_name

    if user_prompts:
        print("Are you absolutely sure you want to continue at this point?")
        print("Things get permanent after this and wireguard will restart once done.")
        you_sure = input("y to continue, anything else will bail: ")

        if you_sure.lower() != "y":
            user_quit()
            

    print("Backing up xml file...", end='')
    try:
        shutil.copy2(opnsense_config_xml, opnsense_config_xml.replace(".xml", ".wgback"))
    except:
        print("Unable to backup xml file. Not proceeding!")
        exit(-1)
    print("Backup successful\n")

    print("Attempting to edit xml file...", end='')
    clients_node = root.findall("./OPNsense/wireguard/client/")[0]

    add_formatted_subelement(clients_node, 
                             "client", 
                             attrib={
                                 'uuid':client_conf['uuid']
                                 }, 
                             children={
                                 'enabled':'0',
                                 'name':client_conf['name'],
                                 'pubkey':client_conf['pubkey'],
                                 'psk':client_conf['psk'],
                                 'tunneladdress':client_conf['tunneladdress'],
                                 'serveraddress': None,
                                 'serverport':server_conf['port'],
                                 'keepalive':'25'
                                 }, 
                             indent="  ")

    # add client to server peer list.
    server_conf['peers'].append(client_conf['uuid'])

    server.find('peers').text = (",".join(server_conf['peers']))
    print("Done...")

    print("Attempting to save xml file...", end='')
    write_succeeded = True
    try:
        tree.write(opnsense_config_xml)
    except:
        write_succeeded = False

    if(not write_succeeded):
        print("Error writing xml file. Restoring backup, just in case...")
        try:
            shutil.copy2(opnsense_config_xml.replace(".xml", ".wgback"), opnsense_config_xml)
        except:
            print("Can't restore xml. You'll need to fix this yourself. Sorry!")
            exit(-1)

    print("Done!")

    print("Attempting to create config file...", end='')
    # Generate client config.
    client_text = f"""
    [Interface]
    PrivateKey = {client_conf['privkey']}
    Address = {client_conf['tunneladdress']}
    DNS = {client_conf['dns']}

    [Peer]
    PublicKey = {server_conf['pubkey']}
    PresharedKey = {server_conf['psk']}
    AllowedIPs = {default_network}
    Endpoint = {server_conf['endpoint']}
    PersistentKeepalive = 25
    """

    client_filename = f"{client_name}.conf"
    client_png = f"{client_name}.png"

    with open(client_filename, "w") as client_conf_file:
        client_conf_file.write(client_text)

    # Restart
    try:
        subprocess.run('configctl wireguard restart', shell=True).check_returncode()
    except subprocess.CalledProcessError:
        print("No biggie, but you'll need to save and restart wireguard yourself.")

    # Sometimes I need to toggle the wireguard instance to make the changes stick.
    # I think it might help if I can figure out the interface and run something like
    #wg-quick down wgx (where x is the interface for the instance)
    #wg-quick up wgx
    # to force the changes to apply.
    
    # show qr code
    if can_qr:       
        res = subprocess.run(f'qrencode -t png -o {client_png} < {client_filename}', shell=True)
        if display_qr:
            input("Displaying QR code. Maximize your screen and hit enter when ready")
            res = subprocess.run(f'qrencode -t ansiutf8 < {client_filename}', shell=True)
        
    print("Done. Now you just need to go into OPNSense, enable the client and hit save!")
    print("There are also .conf (and .png) files for the new client in the root folder. Be sure to secure them.")

def check_package(name, source):
    print(f"Checking for package {name}...", end='')
    has_pkg = True # Think positive!
    try:
        p = subprocess.check_output(f"pkg info {name}", shell=True)
    except subprocess.CalledProcessError:
        has_pkg = False

    if has_pkg:
        print("found!")
        return True

    print("not found!\nAttempting to install...", end='')
    try:
        p = subprocess.check_output(f"pkg add {source}", shell=True)
        print("Successful!")
        return True

    except subprocess.CalledProcessError:
        print("Failed to install: {p.")
        return False

def install_packages():
    if check_package("png", PNG_PKG) is False:
        print("This is a dependency. Will continue without qr code Support.")
        return False
    if check_package("libqrencode", QR_PKG) is False:
        print("The libqrencode package generates the QR code. Will continue without QR code support.")
        return False

    return True

def add_formatted_subelement(root, name, attrib={}, children={}, indent="auto"):
    # See what the node itself uses for formatting.
    root_tail = root.tail
    root_text = root.text

    # attempt to get indentation automatically. Good luck.
    if indent == "auto":
        if len(root) > 0: #if there's children this is the best.
            # get the difference between the text and the tail
            indent = root[-1].text.replace(root[-1].tail, '')
        else:
            # get the difference between the text and the tail
            indent = root_text.replace(root_tail, '');
            # but divide that margin by two because there's no subelements
            indent = indent[:len(indent)//2]
    
    # Now we know our margin, we can also know how deep our element is.
    # keep in mind that the root element will also unindent on the tail,
    level = root_tail.count(indent) + 1 # so we'll add another indent to prevent this.
    element_level = level + 1
    child_level = level + 2

    # add our element
    element = ET.SubElement(root, name, attrib)

    # add our children
    for key, value in children.items():
        child = ET.SubElement(element, key)
        child.text = value

    # if there's children
    if len(element) > 0:
        element.text = "\n" + (indent * child_level)

        # fix up the padding for the children
        for sibling in element:
            sibling.tail = "\n" + (indent * child_level)

        # unindent last sibling
        element[-1].tail = "\n" + (indent * element_level)


    # fix up the padding for the element and its siblings
    for sibling in root:
        sibling.tail = "\n" + (indent * element_level)

    # and unindent that last sibling.
    root[-1].tail = "\n" + (indent * level)

def parse_actions(selection, actions, default = None):
    return actions.get(selection.lower(), default)

def user_quit():
    print("User has quit without making changes.")
    exit(0)

def parse_server_details(server):
    error_message = []
    pubkey = server.findtext('pubkey')
    if pubkey is None:
        error_message.append("public key (pubkey)")

    tunneladdress = server.findtext('tunneladdress')
    if tunneladdress is None:
        error_message.append("tunneladdress")
    
    # Parse out ip address.
    try:
        net = ipaddress.ip_network(tunneladdress, strict = False)
    except:
        error_message.append("available ip range")
    
    # get a list of all the valid ips for this range.
    net_range = list(net.hosts())
    
    # and get the netmask.
    netmask = net.prefixlen

    # remove the netmask
    tunneladdress = tunneladdress.replace(f"/{netmask}", "")
    
    try:
        # parse the actual ip and remove it from range
        net_range.remove(ipaddress.ip_address(tunneladdress))
    except ValueError:
        pass
    except:
        error_message.append("server ip")
    
    port = server.findtext('port')
    if port is None:
        error_message.append("port")

    peers = server.findtext('peers')
    if peers is None or peers == "":
        peers = []
    elif peers.count(",") == 0:
        peers = [peers]
    else:
        peers = peers.split(",")

    if len(error_message) != 0:
        print("We couldn't parse these fields:")
        print("\n".join(error_message))
        exit(-1)

    server_conf = {
        "peers": peers,
        "pubkey": pubkey,
        "tunneladdress": tunneladdress,
        "netmask": netmask,
        "port": port
        }

    client_conf = {
        "net_range": net_range
        }

    return (server_conf, client_conf)

if __name__ == "__main__":
    main()
