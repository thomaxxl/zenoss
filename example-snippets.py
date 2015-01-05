#/opt/zenoss/bin/zendisc run --now -d 10.32.25.146 --monitor localhost --deviceclass /Network/Router/Juniper

/opt/zenoss/bin/zendisc run --now -d 10.32.25.145 --monitor localhost --deviceclass /Network/Switch/Juniper
/opt/zenoss/bin/zendisc run --now -d 10.32.25.166 --monitor localhost --deviceclass /Network/Router/Firewall/Juniper

/opt/zenoss/bin/zendisc run --now -d 10.32.25.2 --monitor localhost --deviceclass /Network/Switch/Nortel/Baystack 
/opt/zenoss/bin/zendisc run --now -d 10.32.25.1 --monitor localhost --deviceclass /Network/Router/Firewall/Netscreen

/opt/zenoss/bin/zendisc run --now -d 10.32.25.22 --monitor localhost --deviceclass "/Appliance/Palo Alto"
/opt/zenoss/bin/zendisc run --now -d 10.32.25.67 --monitor localhost --deviceclass  /Server/Linux


/opt/zenoss/bin/zendisc run --now -d 10.32.27.105 --monitor localhost --deviceclass /Network/Switch/Juniper

reindex()

################################################################################
#
# EVENT HANDLING
#
################################################################################
#event transform example: 
if evt.component == '/mnt/filesystem' and evt.severity != 0:
evt.severity = 2


events = dmd.ZenEventManager.getEventList()
for e in events:
    if e.eventClass == "/Perf/CPU":
        dmd.Events.manage_ackEvents(e.evid)

events = dmd.ZenEventManager.getEventList()
for e in events:
  print e.summary
        
evt._action = 'drop'
evt._action = 'history'                               

events = dmd.ZenEventManager.getEventList()
for e in events:
    try:
        ed = em.getEventDetail(e.evid)
        lifetime = [ int(x[1]) for x in ed.getEventDetails() if x[0] == 'Lifetime' ]
        if lifetime and lifetime[0]:
            lastTime = time.strptime(e.lastTime,"%Y/%m/%d %H:%M:%S.%f")
            lastTime = datetime.fromtimestamp(mktime(lastTime))
            tdelta = datetime.now() - lastTime
            if tdelta.seconds / 3600 > lifetime[0]:
                dmd.ZenEventManager.manage_deleteEvents(e.evid)
    except Exception as e:
        print "failed to process event '%s': %s" % (getattr(e,'evid',''),e)
        
        
        


import re
SNMPTRASH = re.compile('snmp trap nothing of value here', re.IGNORECASE)
if SNMPTRASH.search(evt.message):
  evt.summary = "This is what that trap actually means"
  evt.message = "This is what that trap actually means"
 
EVENT TRANSFORMS & EXAMPLES : http://community.zenoss.org/docs/DOC-2554


List all event transforms:

print "The following event classes have transforms associated with them:"
for ec in [ ec for ec in dmd.Events.getSubOrganizers() if ec.transform ]:
    print ec.getOrganizerName()
    print ec.transform
    print 'X'*80
 
################################################################################
# DEVICE MANAGEMENT
################################################################################
#####
dev=find('10.32.25.145')

re=dev.JuniperRE()[0]

re.RoutingEngineTemp


########
# Remove all devices
for dev in dmd.Devices.getSubDevices():
  print dev.id
  #dev.deleteDevice()
commit()
reindex()
commit()

###
locations = "Antwerp,New York,London,Amsterdam".split(',')

for name in locations:
   dmd.getDmdRoot("Locations").createOrganizer(name)

########
# FIX A BROKEN DEVICESEARCH OR COMPONENTSEARCH CATALOG
problems = True
while problems:
    problems = False
    brains = dmd.Devices.deviceSearch()
    for d in brains:
        try:
            bah = d.getObject()
        except Exception:
            print "Removing non-existent device from deviceSearch: " + d.getPath()
            dmd.Devices.deviceSearch.uncatalog_object(d.getPath())
            problems = True

problems = True
while problems:
    problems = False
    brains = dmd.Devices.componentSearch()
    for d in brains:
        try:
            bah = d.getObject()
        except Exception:
            print "Removing non-existent component from componentSearch: " + d.getPath()
            dmd.Devices.componentSearch.uncatalog_object(d.getPath())
            problems = True
            
commit()

########
# Remove stale entries from the layer3_catalog
brains = dmd.ZenLinkManager.layer3_catalog()
for i in brains:
    try:
        bah = i.getObject()
    except Exception:
        print "Removing non-existent device from layer3_catalog: " + i.getPath()
        dmd.ZenLinkManager.layer3_catalog.uncatalog_object(i.getPath())

        
commit()



##########
# Users & Roles

http://wiki.zenoss.org/ZenDMD_Tip_-_Create_Users_in_a_Jiffy

dmd.ZenUsers.manage_getUserRolesAndPermissions('admin')

roleManager.valid_roles()
roleManager.possible_permissions()

for d in dmd.Devices.getSubDevices():
  if p.match(d.titleOrId()):
    print d.id
    
for d in dmd.ZenUsers.getAllUserSettings():
  print d

for d in dmd.ZenUsers.getAllUserSettings():
  for t in d.getAllActionRules():
    print t
    
dmd.ZenUsers.admin

usersToAdd = ['Guest', 'testUserB', 'testUserC']
usersToAdd = ['admin']
emailDomain = 'securelink.be'
defaultRoles = ['ZenUser','ZenManager','Manager']
roleManager = dmd.acl_users.roleManager
for user in usersToAdd:
    sync()
    un = str(user)
    ue = '%s@%s' % (str(un), str(emailDomain))
    print 'Adding user %s, email %s' % (str(un), str(ue))
    userOb = dmd.ZenUsers.manage_addUser(un, ue)
    for role in defaultRoles:
        print 'Adding %s role from %s' % (str(role), str(userOb.id))
        roleManager.assignRoleToPrincipal(str(role), str(userOb.id))
    userObB = dmd.ZenUsers.getUserSettings(str(userOb.getId()))
    userObB.email = ue
    commit()
    
    
def add_user(name,email,passwd):
  sync()
  roleManager = dmd.acl_users.roleManager
  userOb = dmd.ZenUsers.manage_addUser(name,passwd)
  roleManager.assignRoleToPrincipal('ZenUser', str(userOb.id))
  userObB = dmd.ZenUsers.getUserSettings(str(userOb.getId())) 
  userObB.email = email
  commit()

add_user('sadmin','thomas.pollet@securelink.be','sadmin')
usersToEdit = ['sadmin']
 
roles = ['ZenManager',]
roleManager = dmd.acl_users.roleManager
for user in usersToEdit:
    sync()
    un = str(user)
    userOb = dmd.ZenUsers.getUserSettings(str(un))
    for role in roles:
        print 'Adding %s role from %s' % (str(role), str(userOb.id))
        roleManager.assignRoleToPrincipal(str(role), str(userOb.id))
    commit()


http://wiki.zenoss.org/ZenDMD_Tip_-_Replace_modeler_plugin_programmatically

import zenoss_api
Zenoss = zenoss_api.ZenossAPI('https://127.0.0.1','admin','zenoss')
Zenoss._router_request("DeviceRouter","setZenProperty",[{"uid":"/zport/dmd/Devices/Network/Switch/Juniper/devices/10.32.25.146","zProperty":"ztestvar","value":"y00110"}])
res=Zenoss._router_request("DeviceRouter","getComponents",[{"uid":"/zport/dmd/Devices/Network/Switch/Juniper/devices/10.32.25.166","keys":["uid"]}])
res['result']['totalCount']

r=Zenoss._router_request("DeviceRouter","getComponents",[{"uid":"/zport/dmd/Devices/Network/Switch/Juniper/devices/10.32.25.146/JuniperRE","keys":["uid"]}])

/zport/dmd/Devices/Network/Router/Firewall/Juniper/devices/veritas-srx-shop110/os/interfaces/
r=Zenoss._router_request("DeviceRouter","getComponents",[{"uid":"/zport/dmd/Devices/Network/Router/Firewall/Juniper/devices/veritas-srx-shop110/os/interfaces/","keys":["uid"]}])

def print_components(url):
    r=Zenoss._router_request("DeviceRouter","getComponents",[{"uid":url,"keys":["uid"]}])
    for i in r['result']['data'] : 
        print i['uid']

def print_properties(url):
        


for d in Zenoss.get_devices()['devices']:
    print d['uid']

#Zenoss.set_info(3,deviceClass="/zport/dmd/Devices/Network/Switch/Juniper/devices/10.32.25.146")

d=find('10.32.25.146')

from pynetsnmp.twistedsnmp import AgentProxy
def inner(driver):
  self.log.debug("Checking SNMP community %s on %s",
  device.zSnmpCommunity, device.id)
  oid = ".1.3.6.1.2.1.1.5.0"
  proxy = AgentProxy(device.id,
    device.zSnmpPort,
    timeout=device.zSnmpTimeout,
    community=device.zSnmpCommunity,
    snmpVersion=device.zSnmpVer,
    tries=2)

from pynetsnmp.twistedsnmp import AgentProxy
proxy = AgentProxy('10.32.25.146',
    161,
    timeout=2.5,
    community='securelink',
    snmpVersion='v2c',
    tries=2)
    
'''
set tabstop=4
set shiftwidth=4
set softtabstop=4
set smarttab
set expandtab
'''


#Mysql pass:
>>> dmd.ZenEventManager.username
'zenoss'
>>> dmd.ZenEventManager.password
'zenoss'
>>>

#Delete Events
#!/opt/zenoss/bin/python
 
import Globals
from Products.Zuul import getFacade
from Products.ZenUtils.ZenScriptBase import ZenScriptBase
import time
 
dmd = ZenScriptBase(connect=True).dmd
zep = getFacade('zep')
filter_zep = zep.createEventFilter(status=[0]) #Create filter that looks for all severities, and specifically events that are 'New' status
status,response = zep.closeEventSummaries(eventFilter=filter_zep)
print "status %s -- response %s" % (status,response)


for d in dmd.Devices.getSubDevices():
   for i in d.os.interfaces():
      if i.macaddress == '00:50:56:AA:7C:8D':
         print d.id +" "+ i.macaddress

print i.operStatus         
d.os.interfaces.ae0.operStatus


for dev in dmd.Devices.Network.Switch.Juniper.getSubDevices():
  out = open(dev.name(),'w')
  for i in dev.os.interfaces():
    if i.name().find('ge') == 0:
      out.write(i.name() + ","+ i.getAdminStatusString() +"," + i.getOperStatusString()+"\n")
  out.close()           




for dev in dmd.Devices.Network.Switch.Juniper.getSubDevices():
    for i in dev.os.interfaces():
        print i.ifindex  

oid = '1.3.6.1.2.1.2.2.1.8.' + i.ifindex        
        
         

for dev in dmd.Devices.Network.Switch.Juniper.getSubDevices():
  upcount = 0
  ifcount = 0
  for i in dev.os.interfaces():
    if i.name().find('ge') == 0:
      ifcount += 1
      if i.getOperStatusString().find('Down') < 0:
        upcount += 1
  print "%-32s %-4i %-4i" % (dev.name(), ifcount, upcount)
  
         
import re
ipsearch = re.compile('192\.168\.1\.[0-9]{1,3}')
#for d in dmd.Groups..getSubDevices():
for d in dmd.Devices.getSubDevices():
   for i in d.os.interfaces():
      ipaddress = i.getIpAddress()
      if ipaddress == None:
         continue
      else:
         if ipsearch.search(ipaddress):
            print d.id+" "+ipaddress
            
            
for r in dmd.Devices.Network.Router.Juniper.getSubDevices(): print r.manageIp      

if evt.summary.startswith("Connection to zenoss dmd failed"):
  if device.getPingStatus() > 0:
    evt.severity = 2
  else evt.message += " - No Ping Down!"

###########################################################################
To export a device list:
Go to the ZMI:
http://localhost:8080/zport/dmd/Devices/manage
Make a script object called getMyDeviceList().
Put the following line into the body of the script:
return [ d.id for d in context.getSubDevices() ]
Call it like this:
http://localhost:8080/zport/dmd/Devices/getMyDeviceList
Alternatively, enter the following line to return all device IP addresses:
return [ d.manageIp for d in context.getSubDevices() ]
You can call this method from different parts of the tree to limit the list of devices:
http://localhost:8080/zport/dmd/Devices/Server/Linux/getMyDeviceList                     



Zenoss._router_request("MibRouter","moveNode",[{"uids":["/zport/dmd/Mibs/mibs/AGENTX-MIB"],"target":"/zport/dmd/Mibs/Juniper Networks/JunOS"}])

########################################
import os
import zenoss_api
post = {"action":"DeviceRouter","method":"getComponents",
        "data":
          [{"start":0,"limit":70000,
          "uid":"/zport/dmd/Devices/Network/Router/Firewall/Juniper/devices/10.32.25.166",
          "keys":["uid","severity","status","name","description","ipAddress","ipAddressObjs","network",
                  "macaddress","usesMonitorAttribute","ifStatus","monitor","monitored","locking","duplex","netmask"]
          ,"meta_type":"IpInterface"}],
        "type":"rpc","tid":18}
        
def post_to_rreq(post):
    router  = post["action"]
    method = post["method"]
    data    = post["data"]
    Zenoss  = zenoss_api.ZenossAPI('https://127.0.0.1','admin','zenoss')
    return Zenoss._router_request(router,method,data) 



post_to_rreq(post)
########################################


import os
import zenoss_api
   
uid     = "/zport/dmd/Devices/Network/Router/Firewall/Juniper/devices/10.32.25.166"   
Zenoss  = zenoss_api.ZenossAPI('https://127.0.0.1','admin','zenoss')
req1    = Zenoss.get_components(uid,keys=["name","ifStatus"],meta_type="IpInterface")['data']
if1     = [ ( i['name'] , ( i['ifStatus']['adminStatus'], i['ifStatus']['operStatus'] )) for i in req1 ]
os.system("zenmodeler run --checkstatus -d 10.32.25.166 --collect zenoss.snmp.InterfaceMap")
req2    = Zenoss.get_components(uid,keys=["name","ifStatus"],meta_type="IpInterface")['data']
if2     = [ ( i['name'] , ( i['ifStatus']['adminStatus'], i['ifStatus']['operStatus'] )) for i in req2 ]
dif2    = dict(if2)


for i1 in if1:
    if i1[0] not in dif2.keys():
        print i1
        continue
    if i1[1] != dif2[i1[0]]:
        print dif2[i1[0]]                

# [ ( i1[0],dif2[i1[0]] ) for i1 in if1 if i1[0] not in dif2.keys() or i1[1] != dif2[i1[0]] or i1[1] != dif2[i1[1] ]


#ZODB
fs='/opt/zenoss/var/Data.fs'
from ZODB import FileStorage, DB
storage = FileStorage.FileStorage(fs,read_only=True)
db = DB(storage)
connection = db.open()
root = connection.root()
root.items()
      
      
import os
from ipcalc import IP

if evt.device.find('veritas-srx-shop') == 0:
    srx    = IP(device.manageIp)
    router = IP(srx.ip - 1)
    rping  = os.system("ping -c 1 " + router.to_ipv4() )
    if rping != 0: # suppress
        evt.eventState = 2      
        
        
        
d.os.interfaces.objectValues

${dev/os/interfaces/objectValues}

   
   -----------
   
        
ifcodes = (None,'Up','Down','Testing','Unknown','Dormant','Not Present','Lower Layer Down')

ifcodes = (None,'Up','Down','Testing','Unknown','Dormant','Not Present','Lower Layer Down')

def ignore(dev,interface):
  try:
    lines = open(ifconf).read().splitlines()
    for l in lines:
      try:
        d , i = l.split(' ')
        if i == interface  and  ( d == dev.name() or d == dev.manageIp ) :
          return True
      except: # syntax error, ignore
        pass 
  except IOError:
    pass
  return False


if evt.summary.startswith('threshold of OperStatus'):
    component = evt.component
    if component.find('.') > 0 :
        evt._action = 'drop'
    else:
        operstatus = int(evt.summary[-4:-3])
        for i in device.os.interfaces():
            if i.name() == component: break
        if i.operStatus == operstatus or ignore(device,component):
            evt._action = 'drop'
        else:
            evt.summary = 'Operational status changed from ' + ifcodes[i.operStatus] + ' to ' + ifcodes[operstatus]
            if operstatus != 1 : evt.severity = 5
  

ignore("a","b")

          
          
convert development mode:
 cp $ZENHOME/Products/ZenModel/ZenPackTemplate/* .
 if evt.summary.startswith("Connection to zenoss dmd failed"):
  if device.getPingStatus() > 0:
    evt.severity = 2
    evt._action = "history"
  else: 
    evt.message += " - No Ping Down!"           
    
    
import ironport_transforms
process_evt(evt)


import zenoss_api
Zenoss = zenoss_api.ZenossAPI('https://127.0.0.1','admin','zenoss')

events = dmd.ZenEventManager.getEventList()
for e in events:
  if e.summary.startswith('snmp trap cpuUt'):
    print e.getEventData()
    evid = e.getEventData()[-1]
    r=Zenoss._router_request("EventsRouter","classify",[{"evclass":"/Ironport", "evids":[evid]}])
    print r
    
    

                                                                                       
action: "EventsRouter"
data: [{evclass:/App/Install, evids:[f5457c03-cf1e-4cf4-a770-22869c03a8c8]}]
0: {evclass:/App/Install, evids:[f5457c03-cf1e-4cf4-a770-22869c03a8c8]}
evclass: "/App/Install"
evids: [f5457c03-cf1e-4cf4-a770-22869c03a8c8]
0: "f5457c03-cf1e-4cf4-a770-22869c03a8c8"
method: "classify"
tid: 10
type: "rpc"


{"action":"EventsRouter","method":"classify","data":[{"evclass":"/App/Email","evids":["96e60a3a-7355-495b-8d57-59525dbf0e59"]}],"type":"rpc","tid":6}

POST /zport/dmd/Events/evconsole_router HTTP/1.1



#!/usr/bin/env python

import zenoss_api, sys
Zenoss = zenoss_api.ZenossAPI('https://127.0.0.1','admin','zenoss')

trapname   = sys.argv[1]
evclass    = sys.argv[2]
transform  = sys.argv[3]
description= sys.argv[4]
resolution = sys.argv[5]

import Globals, sys
from Products.ZenUtils.ZenScriptBase import ZenScriptBase
dmd = None
try:
    dmd = ZenScriptBase(connect=True).dmd
except Exception, e:
    print "Connection to zenoss dmd failed: %s\n" % e
    sys.exit(1)
    
    
events = dmd.ZenEventManager.getEventList()
for e in events:
  if e.summary.startswith('snmp trap '+trapname):
    print e.getEventData()
    evid = e.getEventData()[-1]
    print Zenoss._router_request("EventsRouter","classify",[{"evclass":evclass, "evids":[evid]}])


for i in dmd.Events.getSubOrganizers() :
  if i.id.find('Ironport') >= 0 :
    break

for o in i.getSubObjects():
  if o.id == trapname:
    o.transform=transform

        
def find_event_class_key(key,root=None):
  if not root:
    root = dmd.Events
  for n in root.getSubObjects():
    if n.id == key : 
      print "found key ", key
      return True
  for node in root.getSubOrganizers():    
    if find_event_class_key(key,node): 
      return True
  return False
    


find_event_class_key('powerSupplyStatusChange')
                          
from xml.dom import minidom
from urllib import urlopen
import sys
paadd ='87.85.35.60'                          
pauser='securelink'
papass='98!rTzBV'
apiurl='https://'+paadd+'/esp/restapi.esp?'
url   = apiurl+'type=keygen&user='
url  +=pauser +'&password=' +papass

def get_xml(url):
  try:
    res   = urlopen(url)
    xml   = minidom.parse(res) 
    response = xml.getElementsByTagName('response')
    status = response[0].attributes['status'].value
  except:
    print "error"
    sys.exit(1)
      
  if status != "success":
    print "authentication failed"
    sys.exit(1)
    
  return response

res=get_xml(url)  
key=res[0].getElementsByTagName('key')[0].firstChild.nodeValue  
  
url   ='https://'+paadd+'/esp/restapi.esp?key='+key
url  +='&type=op&cmd=<show><high-availability><all></all></high-availability></show>'  

res=get_xml(url)
ha =res[0].getElementsByTagName('enabled')[0].firstChild.nodeValue

if ha != 'yes':
  #no HA
  sys.exit(0)

local = res[0].getElementsByTagName('local-info')
state = local[0].getElementsByTagName('state')[0].firstChild.nodeValue


if evt.severity > 2 and evt.eventState == 0:

  import Globals
  from Products.ZenUtils.ZenScriptBase import ZenScriptBase
  dmd = ZenScriptBase(connect=True, noopts=True).dmd

  dependencies = dev.cDependencies.split(',')
  for d in dependencies:
    if dev.getPingStatus():
      evt.summary += ' - Dependency down'
      evt.severity = 2
    


-avaya test members
-backup log rotation
-scp backup status

/perf/interface transform
/Unknown ignore syslog events + transform die er al staat??
dependencies : generiek


modeler runnen???

if getattr(evt,'severity',0) == 5 and getattr(evt,'agent','') == "zensyslog":
    evt.severity = 4

if getattr(evt,'agent','') == "zensyslog" and getattr(evt, 'prodState', 0) < 400:
   evt._action = "drop"

if getattr(evt,'agent','') == "zensyslog" and dev.cIgnoreUnknownEvents:
  evt._action = "drop"


if dev.cDependencies and evt.severity >= 3:
  deplist = dev.cDependencies.split[',']
  for dep in deplist:
    depd = dmd.Devices.findDevice(dep)
    if router.getPingStatus():
      evt.message = evt.message + " - " + dep + " is Down"
      evt.severity=2
      break
      
      
for pack in dmd.ZenPackManager.packs():
  if pack.id.find('Palo')>0 : break

packables=pack.getSubObjects()[2]

for p in packables(): print p.id      
for p in packables(): print p.getPhysicalPath()


todelete = [ "/PaloAlto/Clear","/PaloAlto/ClearAtInfo","/PaloAlto/Critical","/PaloAlto/Error","/PaloAlto/Warning","/PaloAlto/Info"]
for p in packables():
  try: 
    if p.getDmdKey() in todelete:
      break
  except: 
    pass
    


    def migrate(self, pack):
        dmd = pack.__primary_parent__.__primary_parent__
        try:
            panmib = dmd.findObject('/zport/dmd/Mibs/PAN')
        except:
            return
        parent = panmib.aq_parent
        parent.manage_delObjects([panmib.getId()])
    
    
import Globals, logging
from Products.ZenUtils.ZenScriptBase import ZenScriptBase


dmd = ZenScriptBase(connect=True).dmd
em = dmd.Events.getEventManager()

em.cleanCache()
ed = em.getEventDetail(dedupid='10.32.25.229||/PaloAlto||3|snmp trap panGeneralAuthFailTrap')

    select dedupid, count, severity from status;

dcs={ '/Appliance/BlueCoat/' : 'rancid' ,
      '/Appliance/Infoblox' :  'scp' ,
      '/Appliance/Ironport' :  'rancid' ,
      '/Network' :  'rancid' ,
      '/Appliance/Juniper/NSM' :  'scp' ,
      '/Appliance/Juniper/Secure Access SSLVPN' :  'scp' ,
      '/Appliance/Juniper/UAC' :  'scp' ,
      '/Appliance/Juniper/Trapeze MX' :  'rancid' ,
      '/Appliance/Palo Alto' :  'rancid' ,
      '/Server/SMVA' : 'backup-ninja' }

select evid from status where eventClass = '/Unknown';
select evid, value from detail where name = 'oid';
select value from status join detail where eventClass = '/Unknown' and detail.evid = status.evid and detail.name = 'oid';


import xml.etree.ElementTree as ET
tree = ET.parse('objects.xml')
root = tree.getroot()

objects=root[0][0]
for o in objects:
  if o.attrib['id'] == 'jnxFruNotifOperStatus' : 
    for p in o:
      if p.attrib['id'] == 'oid' :
      #p.text =  
        print p.text


cat /sys/module/sctp/sections/.text



add-symbol-file  net/sctp/sctp.o 0xffffffffa024a000
y
break sctp_datamsg_from_user
break sctp_apply_peer_addr_params

break sctp_sf_do_5_1B_init
break sctp_make_op_error_space
sctp_make_control
sctp_make_op_error_space

net/sctp/sm_make_chunk.c:2248

sctp_verify_init > sctp_verify_param > sctp_process_unk_param > sctp_make_op_error_fixed


puppet apply --verbose --debug --execute 'package {zenoss: ensure => installed}'



mibs=dmd.findObject('/zport/dmd/Mibs/IETF/mibs')
for mib in mibs.objectItemsAll():
    mibmod = mib[1]
    for ois in mibmod.objectItems():
        if ois[0] == 'notifications':
            notifications = ois[1]
            for n in notifications.objectItemsAll():
                notif = n[1] 
                #name eventkey description severity    
                desc = notif.description.replace('\n',' ')
                desc = desc.replace(';','-')
                print "%s;%s;%s;info"%(notif.id , notif.oid, desc)


from Products.Zuul.interfaces import ITreeFacade, IMibFacade, IInfo
mibs=dmd.findObject('/zport/dmd/Mibs/Aruba/mibs')
for mib in mibs.objectItemsAll():
    mibmod = mib[1]
    for ois in mibmod.objectItems():
        if ois[0] == 'notifications':
            notifications = ois[1]

#mibmod.notifications.nodes()

functor=getattr(notifications, 'nodes') 
all = [IInfo(node) for node in functor()]
reverse = dir == 'DESC'
sort='name'
nodes = sorted(all, key=lambda info: getattr(info, sort), reverse=reverse)

from Products import Zuul
Zuul.marshal(nodes)

Zuul.marshal(IInfo(functor()[1]))

./ZenUI3/browser/resources/js/zenoss/MIBs.js
./Zuul/routers/mibs.py
Zuul/facades/mibfacade.py
./Zuul/interfaces/mib.py
./Zuul/infos/mib.py
./ZenModel/MibBase.py
Zuul/facades/mibfacade.py

setContext
router.getInfo

nots=dmd.findObject('/zport/dmd/Mibs/Aruba/mibs/STEELHEAD-MIB/notifications')
for n in nots.objectItemsAll(): print n



f=open('IETF.csv','w')
mibs=dmd.findObject('/zport/dmd/Mibs/IETF/mibs')
for mib in mibs.objectItemsAll():
    mibmod = mib[1]
    for ois in mibmod.objectItems():
        if ois[0] == 'notifications':
            notifications = ois[1]
            for n in notifications.objectItemsAll():
                notif = n[1] 
                #name eventkey description severity    
                desc = notif.description.replace('\n',' ')
                desc = desc.replace(';','-')
                if notif.oid.startswith('1.3.6.1.2'):
                    rest = notif.oid[8:]
                    f.write("%s;%s;%s;info\n"%('mgmt.'+rest , notif.oid, desc))              
                    
                    
                    
i=local0; for k in {debug,info,notice,warning,err,crit,alert,emerg}; do logger -p $i.$k "Test daemon message, facility $i priority $k"; done

logger -p local0.crit "NTP Server Unreachable"                  



def lookup_instance(name):
  for ec in dmd.Events.getSubOrganizers():
    instance = [ e for e in ec.getInstances() if e.id == name ]
    if instance:
      return instance[0]
  return None

  
i = lookup_instance('asymRouteError')
eventclass = i.getParentNode().getOrganizerName()
severity = i.zEventSeverity


for ec in dmd.Events.getSubOrganizers():
  if ec.getInstances():
    print ec.getOrganizerName()
    for i in ec.getInstances():
      print "  ", i.id, i.zEventSeverity


def flatten(nested, flat):
            for i in nested:
                flatten(i, flat) if isinstance(i, list) else flat.append(i)
            return flat
        reverse   = dir == 'DESC'
        obj = self._getObject(uid)
        if isinstance(obj, MibOrganizer):
            mibnodes = []
            for child in obj.children() :
                c, m = self.getMibNodes(child.getPrimaryUrlPath(),limit,start,sort,dir,relation)
                mibnodes = list(set(m+mibnodes))
            return len(mibnodes) , sorted(mibnodes, key=lambda info: getattr(info, sort), reverse=reverse)[start:limit + start]
        functor = getattr(obj, relation, None)
        if functor is None:
            log.warn("Unable to retrieve the relation '%s' from %s",
                     relation, obj.id)
            return 0,[]
        alld      = { IInfo(node).id : IInfo(node) for node in functor() }
        flat      = []
        flatten( [ o.getInstances() for o in self._dmd.Events.getSubOrganizers() ] , flat )
        instances = [ i for i in flat if i.id in alld ]

        for i in instances:
            alld[i.id].eventclass=i.getParentNode().getOrganizerName()
            alld[i.id].severity  =i.zEventSeverity
        all = alld.values()
        f=open('/tmp/getMibNodes','w')
        f.write(str(all))
        return len(all), sorted(all, key=lambda info: getattr(info, sort), reverse=reverse)[start:limit + start]
  
  
for i in dmd.Events.getInstances():
  if i.id in sevs:
    print i
    i.zEventSeverity = sevs[i.id][-1]
  else:
    print 'not' , i
