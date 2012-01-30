import netifaces

print 'Found interfaces:'
for iface in netifaces.interfaces():
    print '  %s' % iface

print '\n'

for iface in netifaces.interfaces():
    allAddrs = netifaces.ifaddresses(iface)

    print 'Interface %s:' % iface

    for family,addrs in allAddrs.iteritems():
        fam_name = netifaces.address_families[family]
        print '  Address family: %s' % fam_name
        for addr in addrs:
            print     '    Address  : %s' % addr['addr']
            nmask = addr.get('netmask', None)
            if nmask:
                print '    Netmask  : %s' % nmask
            bcast = addr.get('broadcast', None)
            if bcast:
                print '    Broadcast: %s' % bcast

    print '\n'
