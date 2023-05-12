#!/usr/bin/env python3

# Parse /var/log/apache/access.log and /var/log/auth.log files into lists
# Count number of hits from each unique IP
# Use Shodan.io to determine a location for each IP if possible
# Create CSV with summary of the Shodan and log info
# Plot the locations returned by Shodan with Cartopy

import re # authlog has inconsistent formatting
import time # needed to put a delay between Shodan queies to prevent flooding
import shodan
from datetime import date
from datetime import timedelta
import cartopy.crs as ccrs
import cartopy.feature as cfeature
import matplotlib.pyplot as plt

debugOn = False
yesterday = date.today() - timedelta(days = 1)
yesterdayString = yesterday.strftime('%Y') + '_' + yesterday.strftime('%m') + '_' + yesterday.strftime('%d')

# I am taking /var/log/apache2/access.log.1 and /var/log/auth.log.1 and renaming those to [type]_[date].log with a different script, you will have to
# adjust the code below to suit how you are handleing your logs. I have also changed auth.log to be rotated daily instead of weekly to prevent
# overlaping multiple days of entries on a single map.
# \/------Modify below to suit your own setup------\/

apacheLogName = 'apache_' + yesterdayString + '.log' # I hand acces.logs to this script in the format of apache_YYYY_MM_DD.log
sshdLogName = 'auth_' + yesterdayString + '.log' # I hand auth.logs to this script in the format of auth_YYYY_MM_DD.log
csvOutputName = 'ipList_' + yesterdayString + '.csv' # daily lits of IPs are saved to a csv, I use the format iplist_YYYY_MM_DD.log
mapOutputName = 'map_' + yesterdayString + '.png' # maps are output in the format map_YYYY_MM_DD.png
apacheLogLocation = '' # Location of access.log
sshdLogLocation = '' # Location of auth.log
csvOutputLocation = '' # Location to save csv
mapOutputLocation = '' # Location to save .png
api = shodan.Shodan('YOUR API KEY GOES HER') # its a secret

ipListApache = [] # list of all in apache access.log
ipListSSHD = [] # list of all sshd hit in auth.log
ipUniqueApache = [] # list of unique IPs and hitcount from apache access.log
ipUniqueSSHD = [] # list of unique IPs and sshd hitcount trom auth.log
ipUniqueFull = [] # full list of unique IP's, hitcount, service and Shodan data
known = 0
unknown = 0


def debugPrint(message):
    if debugOn:
        print(message)


debugPrint('Expected access.log File: ' + apacheLogLocation + apacheLogName)
debugPrint('Expected auth.log File: ' + sshdLogLocation + sshdLogName)
debugPrint('CSV Output File: ' + csvOutputLocation + csvOutputName)

# split each line into the following, splitting on " first prevents unpredictable number of elements
# original line: 209.141.56.209 - - [31/Oct/2021:00:54:46 -0400] "GET / HTTP/1.1" 200 284 "-" "Linux Gnu (cow)"
# entry list: [209.141.56.209, -, -, 31/Oct/2021:00:54:46, -0400, GET / HTTP/1.1200 284, -, Linux Gnu (cow)]
try:
    with open(apacheLogLocation + apacheLogName, 'r') as logFile:
        for line in logFile:
            entry = line.replace('" ', '').split('"') # remove trailing "s on quoted parts of entry and then split on "
            entry = entry[0].replace('[', '').replace(']', '').split() + entry # remove []s and split the zeroth entry on spaces
            del entry[5] # remove duplicate entry that was split on previous line
            del entry[-1] # remove empty trailing entry
            ipListApache.append(entry[0]) # list of all apache IPs
            ipUniqueApache = list(dict.fromkeys(ipListApache)) # list of unique apache IPs
except IOError:
    debugPrint('IO error apache log')
    exit()

for i in range(len(ipUniqueApache)):
    ipUniqueApache[i] = [ipUniqueApache[i], ipListApache.count(ipUniqueApache[i]), 'apache'] # append nuber of occurances of each IP to entry and service
    debugPrint(ipUniqueApache[i])

try:
    with open(sshdLogLocation + sshdLogName, 'r') as logFile:
        for line in logFile:
            sshdEntry = re.search('sshd', line) # check each line for SSHD logs
            ipPresent = re.search('(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])', line) # check each line for an IP
            if sshdEntry and ipPresent: # if line is an SSHD log AND has an IP add it to the ipList
                ipListSSHD.append(ipPresent.group()) # list of all sshd IPs
                ipUniqueSSHD = list(dict.fromkeys(ipListSSHD)) # list of all unique sshd IPs
except IOError:
    debugPrint('IO error sshd log')

for i in range(len(ipUniqueSSHD)):
    ipUniqueSSHD[i] = [ipUniqueSSHD[i], ipListSSHD.count(ipUniqueSSHD[i]), 'sshd'] # append nuber of occurances of each IP to entry and service
    debugPrint(ipUniqueSSHD[i])

ipUniqueApache.sort(reverse = True, key = lambda row: row[1]) # sort by number of connection attempts
ipUniqueSSHD.sort(reverse = True, key = lambda row: row[1]) # sort by number of connection attempts

ipUniqueFull = ipUniqueApache + ipUniqueSSHD
ipUniqueFull.sort(reverse = True, key = lambda row: row[1]) # sort by number of connection attempts
debugPrint(ipUniqueFull)

# Get Shodan info and format data as follows
# Unique Ip Entry = [str(IP), int(hits), str(apache/sshd), str(country), str(city), float(longitude), float(latitude), str(isp)]
for h in range(len(ipUniqueFull)):
    time.sleep(1)
    try:
        time.sleep(1)
        host = api.host(ipUniqueFull[h][0])   
        ipUniqueFull[h] = ipUniqueFull[h] + [host['country_name'], host['city'], host['longitude'], host['latitude'], host['isp']]
        known += 1 # count number of good results from Shodan
    except:
        time.sleep(1)
        ipUniqueFull[h] = ipUniqueFull[h] + ['-', '-', 0, 0, '-']
        unknown += 1 # count number of null results from Shodan
    debugPrint(ipUniqueFull[h])

#   line0: [log name],[log date],Unique IPs:,[unique ip count],Total Hits:,[total hit count]
#   line1: IP,Hits,Service,Country,City,Longitude,Latitude,Isp
# linen>1: [IP],[no of hits],[apache/sshd],[shodan country],[shodan city],[shodan longitude],[shodan latitude],[shodan ISP]
with open(csvOutputLocation + csvOutputName, 'w+', newline='') as csvFile:
    csvFile.write('Ip Log,'+ yesterdayString + ',Unique IPs:,' + str(len(ipUniqueFull)) + ',Total Hits:,' + str(len(ipListApache) + len(ipListSSHD)) + '\n')
    csvFile.write('IP,Hits,Service,Country,City,Longitude,Latitude,Isp\n')
    for h in range(len(ipUniqueFull)):
        csvFile.write(ipUniqueFull[h][0] + ',' + str(ipUniqueFull[h][1]) + ',' + str(ipUniqueFull[h][2]) + ',' + ipUniqueFull[h][3].replace(',', '') + ',' + ipUniqueFull[h][4].replace(',', '') + ',' + str(ipUniqueFull[h][5]) + ',' + str(ipUniqueFull[h][6]) + ',' + ipUniqueFull[h][7].replace(',', '') + '\n')

# Setup map
ax = plt.axes(projection=ccrs.PlateCarree()) # pick projection
ax.set_extent([-180, 180, -90, 90], ccrs.PlateCarree()) # crop at full size
ax.coastlines(linewidth=0.5, resolution='110m') # add coasline
ax.add_feature(cfeature.LAND, color='black') # add land and water features
ax.add_feature(cfeature.LAKES, color='#002244')
ax.add_feature(cfeature.OCEAN, color='#002244')
ax.add_feature(cfeature.BORDERS, linewidth=0.1, edgecolor='white') # add country boarders
plt.title(yesterdayString, color='grey') # add a title

for i in range(len(ipUniqueFull)):
    if ipUniqueFull[i][5] != 0 and ipUniqueFull[i][6] != 0 and ipUniqueFull[i][5] is not None and ipUniqueFull[i][6] is not None: # if the IP has valid coordinates plot them
        if ipUniqueFull[i][2] == 'apache': # apache gets red markers
            plt.plot(ipUniqueFull[i][5], ipUniqueFull[i][6], markersize=0.5, color='red', marker='>')
        if ipUniqueFull[i][2] == 'sshd': # sshd gets yellow markers
            plt.plot(ipUniqueFull[i][5], ipUniqueFull[i][6], markersize=0.5, color='yellow', marker='<')

debugPrint('Known Locaiton: ' + str(known))
debugPrint('Unknown Location: ' + str(unknown))

# add some info to the map
plt.text(-175, -15, 'Total Hits: ' + str(len(ipListApache) + len(ipListSSHD)), color='grey', fontsize=5)
plt.text(-175, -20, 'Total Unique: ' + str(len(ipUniqueFull)), color='grey', fontsize=5)
plt.text(-175, -25, 'Known Location: ' + str(known), color='grey', fontsize=5)
plt.text(-175, -30, 'UnKnown Location: ' + str(unknown), color='grey', fontsize=5)

plt.savefig(mapOutputLocation + mapOutputName, dpi=200, bbox_inches='tight', facecolor='black')
