#!/usr/bin/env python

'''
Nagios plugin to perform SNMP queries against Infortrend based RAIDs, this
includes Sun StorEdge 3510 and 3511 models. Parses the results and gives
an overall view of the health of the RAID.

Version: 1.7                                                                
Created: 2009-10-30                                                      
Author: Erinn Looney-Triggs
Revised: 2009-11-23
Revised by: Erinn Looney-Triggs


License:
    check_infortrend, performs SNMP queries again Infortrend based RAIDS
    Copyright (C) 2009  Erinn Looney-Triggs

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

'''

#TODO:
# doctests

import os
import subprocess
import sys

__author__ = 'Erinn Looney-Triggs'
__credits__ = ['Erinn Looney-Triggs', ]
__license__ = 'AGPL 3.0'
__maintainer__ = 'Erinn Looney-Triggs'
__email__ = 'erinn.looneytriggs@gmail.com'
__version__ = 1.7
__status__ = 'Development'

# Nagios exit codes in English
UNKNOWN  = 3
CRITICAL = 2
WARNING  = 1
OK       = 0

class Snmp(object):
    '''
    A Basic Class for an SNMP session
    '''
    def __init__(self, version='2c', destHost='localhost', community='public',
                verbose=0):

        self.community = community
        self.destHost = destHost 
        self.verbose = verbose
        self.version = version

    def query(self, snmpCmd, oid):
        '''
        Creates an SNMP query session. 
        
        snmpcmd is a required string that can either be 'snmpget' 
        or 'snmpwalk'.
        
        oid is a required string that is the numerical OID to be used.
        '''
        
        fullSnmpCmd = self.__which(snmpCmd)
        
        if not fullSnmpCmd:
            print snmpCmd, ('is not available in your path, or is not '
                            'executable by you, exiting.')
            sys.exit(CRITICAL)
            
        cmdLine = ('{snmpCmd} -v {version} -O v -c {community} '
                   '{destHost} {oid}')
        
        cmdLine = cmdLine.format(snmpCmd = snmpCmd, version = self.version,  
                                 community = self.community, 
                                 destHost= self.destHost, 
                                 oid = oid,)
        
        if self.verbose > 1:
            print 'Debug2: Performing SNMP query:', cmdLine
        
        try:
            p = subprocess.Popen(cmdLine, shell=True, 
                                 stdout = subprocess.PIPE, 
                                 stderr = subprocess.STDOUT)
        except OSError:
            print 'Error:', sys.exc_info, 'exiting!'
            sys.exit(WARNING) 
        
        # This is where we sanitize the output gathered.
         
        output = p.stdout.read().strip()
        
        if self.verbose > 1:
            print 'Debug2: Raw output obtained from query:', output
        
        return self._parseSnmpOutput(snmpCmd, output)
       
    def _parseSnmpOutput(self, snmpCmd, output):
        '''
        Parse the SNMP output and return values as integers or strings.
        Returns a list of items for walk and a single item for gets. 
        '''
        finalOutput = []       
            
        for item in output.split('\n'):
            try:
                style, value = item.split(':')
            except ValueError:
                # If exception occurs this is probably a warning message
                # pass through.
                style = None
                value = item
            
            if style == 'INTEGER':
                finalOutput.append(int(value))
            elif style == 'STRING':
                # Strip whitespace, quotes, then whitespace again
                finalOutput.append(value.strip().strip('"').strip())
            else:
                # We treat any unknowns as strings
                finalOutput.append(value)
        
        if snmpCmd == 'snmpget':
            finalOutput = finalOutput[0]
        
        if self.verbose > 1:
            print 'Debug2: Final output after cleaning:{0}'.format(finalOutput)
            
        return finalOutput
    
    def __which(self, program):
        '''This is the equivalent of the 'which' BASH built-in with a 
        check to make sure the program that is found is executable.
        '''
        
        def is_exe(file_path):
            '''
            Tests that a file exists and is executable.
            '''
            return os.path.exists(file_path) and os.access(file_path, os.X_OK)
        
        file_path = os.path.split(program)[0]
        
        if file_path:
            if is_exe(program):
                return program
        else:
            for path in os.environ["PATH"].split(os.pathsep):
                exe_file = os.path.join(path, program)
                if is_exe(exe_file):
                    return exe_file
    
        return None

class CheckInfortrend(Snmp):
    '''
    Main class that performs checks against the passed in RAID, this class 
    inherits from Snmp so Snmp is required or a suitable substitute needs
    to be made.
    
    There are four optional arguments that are passed to the init constructor:
    community: a string giving the community password
    desthost: a string giving the destination host as either an IP for FQDN
    verbose: a integer, any number other than zero will give you verbose output
    version: a string specifying the SNMP version to use only 1, and 2c are
    supported
    '''
    
    def __init__(self, community='public', destHost='localhost', 
                 verbose=0, version='2c'):
        
        # Base OID found during auto detect
        self.baseoid = ''
        
        # Holder for state counts
        self.state = {'critical' : 0, 'unknown': 0, 'warning' : 0}
        
        # Holder for nagios output and perfdata output
        self.output = []
        self.perfData = []
        
        # Initialize our superclass
        Snmp.__init__(self, version, destHost, community, verbose)
        
    def autoDetect(self):
        '''
        Perform auto detection on designated SNMP agent in order 
        to determine which base OID to use.
        
        There can be more OIDs, and I am sure there are. Just add the base OID
        to the list and the agent can be detected.
        
        This method expects no arguments.
        '''
        
        # Infortrend's base oid: 1.3.6.1.4.1.1714.
        # Sun's base oid for 3510: 1.3.6.1.4.1.42.2.180.3510.1.
        # Sun's base oid for 3511: 1.3.6.1.4.1.42.2.180.3511.1.
        
        baseoids = ['1.3.6.1.4.1.1714.', '1.3.6.1.4.1.42.2.180.3510.1.', 
                    '1.3.6.1.4.1.42.2.180.3510.1.',]
        
        for baseoid in baseoids:
            result = self.query('snmpget', baseoid + '1.1.1.10.0')
            
            if result != 'No Such Object available on this agent at this OID':
                self.baseoid = baseoid
                break
        
        if not self.baseoid:
            print ('Unable to auto detect array type at host: {0}, '
                   'exiting.').format(self.destHost)
            sys.exit(CRITICAL)
        
        if self.verbose > 1:
            print 'Debug 2: Base OID set to:', self.baseoid
        
        return None
       
    def checkAll(self):
        '''
        Convenience method that will run all of the checks against the 
        RAID.
        
        This method expects no arguments.
        '''
        
        self.autoDetect()
        self.checkModelFirmware()
        self.checkDriveStatus()
        self.checkDeviceStatus()
        self.parsePrintExit()
        
        return None
    
    def __checkBattery(self, deviceDescription, status, sensorValue):
        '''
        For internal use, checks the battery status. Expects a string for
        the deviceDescription, an integer for the status and an integer for
        the sensorValue.
        '''
        
        # If status is 0 everything is copacetic
        if status != 0:
            outputLine = []
            
            outputLine.append(deviceDescription + ':') # Begin our output line
                
            binary = self._convertIntegerToBinaryAndFormat(status)
            
            if self.verbose > 1:
                print ('Debug2: Device: {0}, Value:{1}, Status code:{2} '
                       'binary:{3}').format(deviceDescription, sensorValue, 
                                            status, binary)
            
            try:   
                if binary[-1] == '1':
                    outputLine.append('Battery is malfunctioning')
                    self.state['critical'] += 1
            except IndexError:
                pass
            
            try:
                if binary[-2] == '1':
                    outputLine.append('Battery charging on')
                    self.state['warning'] += 1
            except IndexError:
                pass
            
            try: 
                numeral = self._convertBinarytoInteger(binary[-4:-2])
            
                if numeral == 1:
                    outputLine.append('Battery not fully charged')
                    self.state['warning'] += 1
                elif numeral == 2:
                    outputLine.append('Battery charge critically low') 
                    self.state['critical'] += 1
                elif numeral == 3:
                    outputLine.append('Battery completely drained')
                    self.state['critical'] += 1
                 
            except IndexError:
                pass
                
            try:
                if binary[-7] == '1':
                    # This is a normal state on cheaper RAIDs thus no warning 
                    outputLine.append('Battery-backup is disabled')
            except IndexError:
                pass
            
            try:
                if binary[-8] == '1':
                    outputLine.append('Battery is not present')
                    self.state['critical'] += 1
            except IndexError:
                pass
            
            self.output.append(' '.join(outputLine))           
        
        return None
    
    def __checkCurrentSensor(self, deviceDescription, status, sensorValue):
        '''
        For internal use, checks the current sensor status. Expects a 
        string for the deviceDescription, an integer for the status and 
        an integer for the sensorValue.
        '''
        
        if status != 0:
            outputLine = []
            
            outputLine.append(deviceDescription + ':') # Begin our output line
                
            binary = self._convertIntegerToBinaryAndFormat(status)
            
            if self.verbose > 1:
                print ('Debug2: Device: {0}, Value:{1}, Status code:{2} '
                       'binary:{3}').format(deviceDescription, sensorValue, 
                                            status, binary)
            
            try:   
                if binary[-1] == '1':
                    outputLine.append('Current sensor malfunctioning')
                    self.state['critical'] += 1
            except IndexError:
                pass
               
            try: 
                numeral = self._convertBinarytoInteger(binary[-4:-1])
            
                if numeral == 3:
                    outputLine.append('Over current warning')
                    self.state['warning'] += 1
                elif numeral == 5:
                    outputLine.append('Over current limit exceeded')
                    self.state['critical'] += 1
            except IndexError:
                pass
                
            try:
                if binary[-7] == '1':
                    outputLine.append('Current sensor is not activated')
                    self.state['warning'] += 1
            except IndexError:
                pass
            
            try:
                if binary[-8] == '1':
                    outputLine.append('Current sensor not present')
                    self.state['critical'] += 1
            except IndexError:
                pass
            
            self.output.append(' '.join(outputLine))           
        
        return None
    
    def __checkDoor(self, deviceDescription, status, sensorValue):
        '''
        For internal use, checks the current sensor status. Expects a 
        string for the deviceDescription, an integer for the status and 
        an integer for the sensorValue.
        '''
        
        if status != 0:
            outputLine = []
            
            outputLine.append(deviceDescription + ':') # Begin our output line
                
            binary = self._convertIntegerToBinaryAndFormat(status)
            
            if self.verbose > 1:
                print ('Debug2: Device: {0}, Value:{1}, Status code:{2} '
                       'binary:{3}').format(deviceDescription, sensorValue, 
                                            status, binary)
            
            try:   
                if binary[-1] == '1':
                    outputLine.append('Door, door lock, or door sensor '
                                      'malfunctioning')
                    self.state['critical'] += 1
            except IndexError:
                pass
            
            try:
                if binary[-2] == '1':
                    outputLine.append('Door is open')
                    self.state['warning'] += 1
            except IndexError:
                pass
                
            try:
                if binary[-7] == '1':
                    outputLine.append('Door lock not engaged')
                    self.state['warning'] += 1
            except IndexError:
                pass
            
            try:
                if binary[-8] == '1':
                    outputLine.append('Door is not present')
                    self.state['critical'] += 1
            except IndexError:
                pass
            
            self.output.append(' '.join(outputLine))           
        
        return None
    
    def __checkFan(self, deviceDescription, status, sensorValue):
        '''
        For internal use, checks the fan status. Expects a string 
        for the deviceDescription, an integer for the status and an 
        integer for the sensorValue.
        
        Conversions for fan speed:
        12292 < 4000 rpm
        77828 = 4000 - 4285 rpm
        143364 = 4286 - 4570 rpm
        208900 = 4571 - 4856 rpm
        274436 = 4857 - 5142 rpm
        339972 = 5143 - 5428 rpm
        405508 = 5429 - 5713 rpm
        471044 > 5713 rpm
        
        Unfortunately, because we are not receiving the actual fan speed
        warning and critical thresholds can't be used. In order to graph
        this data I chose the top value for each choice, this is not as 
        detailed as I would like but it should give you an idea.
        '''
        
        fanSpeeds = {12292:4000,
                     77828:4285,
                     143364:4570,
                     208900:4571,
                     274436:4857,
                     339972:5428,
                     405508:5713,
                     471044:5800,
                     }
        
        warnRPM = '6000'
        critRPM = '7000'
        minRPM = '0'
        maxRPM = '8000'
        
        if self.verbose > 1:
            print 'Debug2: Fan speed is:{0} rpm.'.format(fanSpeeds[sensorValue])
        
        self.perfData.append("'{0}'={1};{2};{3};{4};{5}"
                             .format(deviceDescription, 
                                     fanSpeeds[sensorValue], warnRPM,
                                     critRPM, minRPM, maxRPM))
        
        if status != 0:
            outputLine = []
            
            outputLine.append(deviceDescription + ':') #Begin our output line
                
            binary =self._convertIntegerToBinaryAndFormat(status)
            
            if self.verbose > 1:
                print ('Debug2: Device: {0}, Value:{1}, Status code:{2} '
                       'binary:{3}').format(deviceDescription, sensorValue, 
                                            status, binary)
            
            try:   
                if binary[-1] == '1':
                    outputLine.append('Fan is malfunctioning')
                    self.state['critical'] += 1
            except IndexError:
                pass
                
            try:
                if binary[-7] == '1':
                    outputLine.append('Fan is off')
                    self.state['warning'] += 1
            except IndexError:
                pass
            
            try:
                if binary[-8] == '1':
                    outputLine.append('Fan is not present')
                    self.state['critical'] += 1
            except IndexError:
                pass
            
            self.output.append(' '.join(outputLine))           
        
        return None
    
    def __checkHddModelSerialNumber(self, hdd):
        '''
        For internal use, grabs the model and serial number for the d
        rive number that is passed in and appends it to the nagios output. 
        This is designed to be used when a failed drive is detected, 
        the model and serial number is grabbed for convenience. 
        It can however, be used for other purposes. Takes one argument hdd 
        which is an int of the drive you wish to check.
        '''
        hddModel = ('Hard Drive Model:', 
                    self.baseoid + '1.6.1.15.' + str(hdd), 'snmpget')
        hddSerialNum = ('Hard Drive Serial Number:', 
                        self.baseoid + '1.6.1.17.' + str(hdd),
                        'snmpget')
        
        model = self.__query(hddModel)[1]
        self.output.append('model:{0}'.format(model))
        serialNumber = self.__query(hddSerialNum)[1]
        self.output.append('serial number:{0}'.format(serialNumber))
        
        
        return None
    
    def __checkHddStatus(self, hdds):
        '''
        For internal use, parses list returned from hddStatus OID and checks
        for error conditions. Requires one argument hdds which has to be a 
        list of one or more return values from hddStatus OID.
        '''
        
        # For completeness here are the codes that we accept as being
        # good.
        # 1 : On-Line Drive
        # 2 : Used Drive
        # 3 : Spare Drive
        # 9 : Global Spare Drive
        # 18 : Drive is a valid Clone of another Drive
        # 128 to 143 : SCSI Device
        
        warningCodes  = {0:'New (Unassigned) Drive', 
                         4:'Drive Initialization in Progress', 
                         5:'Drive Rebuild in Progress', 
                         6:'Add Drive to Logical Drive in Progress', 
                         17:'Drive is in process of Cloning another Drive', 
                         19:'Drive is in process of Copying from another Drive'
                         }
        
        criticalCodes = {63:'Drive Absent', 
                         252:'Missing Global Spare Drive', 
                         253:'Missing Spare Drive', 
                         254:'Missing Drive',
                         255:'Failed Drive'
                         }
        
        for drive, status in enumerate(hdds):
            if self.verbose > 1:
                print 'Debug2: checking drive:', drive, 'with status:', status
            
            if status in criticalCodes:
                self.state['critical'] += 1
                self.output.append('Drive ' + str(drive + 1) + ': ' 
                                + criticalCodes[status])
                
                # Grab the serial if the drive has failed, for lazy admins
                if status == 255:
                    self.__checkHddModelSerialNumber(drive)
                
            elif status in warningCodes:
                self.state['warning'] += 1
                self.output.append('Drive ' + str(drive + 1) + ': ' 
                                + warningCodes[status])
            
        return None
    
    def __checkLdStatus(self, logicalDrives):
        '''
        For internal use. Check the status of the logical drives, expects 
        a list of strings gathered from the ldStatus OID.
        '''

        warningCodes = {1:'Rebuilding', 
                        2:'Initializing', 
                        3:'Degraded',
                        }
        
        criticalCodes = {4:'Dead', 
                         5:'Invalid', 
                         6:'Incomplete', 
                         7:'Drive Missing',
                         64:'Logical Drive Off-line'
                         }
        
        for drive, status in enumerate(logicalDrives):
            if self.verbose > 1:
                print ('Debug2: Checking logical drive: '
                       '{0} with status: {1}').format(drive, status)
            
            if status in criticalCodes:
                self.state['critical'] += 1
                self.output.append('Logical Drive ' + str(drive + 1) + ': ' 
                            + criticalCodes[int(status)])
                
            elif int(status) in warningCodes:
                self.state['warning'] += 1
                self.output.append('Logical Drive ' + str(drive + 1) + ': ' 
                                + warningCodes[int(status)])      
        
        return None
    
    def __checkPowerSupply(self, deviceDescription, status, sensorValue):
        '''
        For internal use, checks the Power supply status. Expects a string 
        for the deviceDescription, an integer for the status and an 
        integer for the sensorValue.
        '''
        
        if status != 0:
            outputLine = []
            
            outputLine.append(deviceDescription + ':') #Begin our output line
                
            binary = self._convertIntegerToBinaryAndFormat(status)
            
            if self.verbose > 1:
                print ('Debug2: Device: {0}, Value:{1}, Status code:{2} '
                       'binary:{3}').format(deviceDescription, sensorValue, 
                                            status, binary)
            
            try:   
                if binary[-1] == '1':
                    outputLine.append('Power supply is malfunctioning')
                    self.state['critical'] += 1
            except IndexError:
                pass
                
            try:
                if binary[-7] == '1':
                    outputLine.append('Power supply is off')
                    self.state['warning'] += 1
            except IndexError:
                pass
            
            try:
                if binary[-8] == '1':
                    outputLine.append('Power supply is not present')
                    self.state['critical'] += 1
            except IndexError:
                pass
            
            self.output.append(' '.join(outputLine))           
        
        return None
    
    def __checkSpeaker(self, deviceDescription, status, sensorValue):
        '''
        For internal use, checks the speaker status. Expects a 
        string for the deviceDescription, an integer for the status and 
        an integer for the sensorValue.
        '''
        
        if status != 0:
            outputLine = []
            
            outputLine.append(deviceDescription + ':') # Begin our output line
                
            binary = self._convertIntegerToBinaryAndFormat(status)
            
            if self.verbose > 1:
                print ('Debug2: Device: {0}, Value:{1}, Status code:{2} '
                       'binary:{3}').format(deviceDescription, sensorValue, 
                                            status, binary)
            
            try:   
                if binary[-1] == '1':
                    outputLine.append('Speaker is malfunctioning')
                    self.state['critical'] += 1
            except IndexError:
                pass
                
            try:
                if binary[-7] == '1':
                    outputLine.append('Speaker is off')
                    self.state['warning'] += 1
            except IndexError:
                pass
            
            try:
                if binary[-8] == '1':
                    outputLine.append('Speaker is not present')
                    self.state['critical'] += 1
            except IndexError:
                pass
            
            self.output.append(' '.join(outputLine))           
        
        return None
    
    def __checkSlotStates(self, deviceDescription, status, sensorValue):
        '''
        For internal use, checks the slot status. Expects a 
        string for the deviceDescription, an integer for the status and 
        an integer for the sensorValue.
        '''
        
        if status != 0:
            outputLine = []
            
            outputLine.append(deviceDescription + ':') # Begin our output line
                
            binary = self._convertIntegerToBinaryAndFormat(status)
            
            if self.verbose > 1:
                print ('Debug2: Device: {0}, Value:{1}, Status code:{2} '
                       'binary:{3}').format(deviceDescription, sensorValue, 
                                            status, binary)
            
            try:   
                if binary[-1] == '1':
                    outputLine.append('Slot sense circuitry is malfunctioning')
                    self.state['critical'] += 1
            except IndexError:
                pass
            
            try:
                if binary[-2] == '1':
                    outputLine.append('Device in slot has been marked bad '
                                      'and is awaiting a replacement')
                    self.state['warning'] += 1
            except IndexError:
                pass
            
            try:
                if binary[-3] == '1':
                    outputLine.append('Slot is not activated')
                    self.state['warning'] += 1
            except IndexError:
                pass
            
            try:
                if binary[-7] == '1':
                    outputLine.append('Slot is ready for insertion/removal')
            except IndexError:
                pass
            
            try:
                if binary[-8] == '1':
                    outputLine.append('Slot is empty')
                    self.state['warning'] += 1
            except IndexError:
                pass
            
            self.output.append(' '.join(outputLine))           
        
        return None
    
    def __checkTempSensor(self, deviceDescription, status, sensorValue):
        '''
        For internal use, checks the temperature sensor and returns the 
        value as perfdata to be used by nagios. Expects a string for
        the deviceDescription, an integer for the status and an integer for
        the sensorValue.
        '''
        
        # Temperature is in Celcius
        temperature = (sensorValue / 2 ** 17 )  - 274
        
        warnTemp = '70'
        critTemp = '80'
        minTemp = '0'
        maxTemp = '100'
        
        self.perfData.append("'{0}'={1};{2};{3};{4};{5}"
                             .format(deviceDescription, temperature, warnTemp,
                                     critTemp, minTemp, maxTemp))
        
        # If status is 0 everything is copacetic
        if status != 0:
            outputLine = []
            
            outputLine.append(deviceDescription + ':') #Begin our output line
                
            binary = self._convertIntegerToBinaryAndFormat(status)
            
            if self.verbose > 1:
                print ('Debug2: Device: {0}, Value:{1}, Status code:{2} '
                       'binary:{3}').format(deviceDescription, sensorValue, 
                                            status, binary)
            
            try:   
                if binary[-1] == '1':
                    outputLine.append('Temperature sensor is malfunctioning')
                    self.state['critical'] += 1
            except IndexError:
                pass
            
            try: 
                numeral = self._convertBinarytoInteger(binary[-4:-1]) 
            
                if numeral == 2:
                    outputLine.append('Cold temperature warning')
                    self.state['warning'] += 1
                elif numeral == 3:
                    outputLine.append('Hot temperature warning') 
                    self.state['warning'] += 1
                elif numeral == 4:
                    outputLine.append('Cold temperature limit exceeded')
                    self.state['critical'] += 1
                elif numeral == 5:
                    outputLine.append('Hot temperature limit exceeded')
                    self.state['critical'] += 1
                    
            except IndexError:
                pass
                
            try:
                if binary[-7] == '1':
                    outputLine.append('Temperature sensor is not activated')
                    self.state['warning'] += 1
            except IndexError:
                pass
            
            try:
                if binary[-8] == '1':
                    outputLine.append('Temperature sensor is not present')
                    self.state['critical'] += 1
            except IndexError:
                pass
            
            self.output.append(' '.join(outputLine))           
        
        return None
    
    def __checkUPS(self, deviceDescription, status, sensorValue):
        '''
        For internal use, checks the UPS status. Expects a string for
        the deviceDescription, an integer for the status and an integer for
        the sensorValue.
        '''
        if status != 0:
            outputLine = []
            
            outputLine.append(deviceDescription + ':') #Begin our output line
                
            binary = self._convertIntegerToBinaryAndFormat(status)
            
            if self.verbose > 1:
                print ('Debug2: Device: {0}, Value:{1}, Status code:{2} '
                       'binary:{3}').format(deviceDescription, sensorValue, 
                                            status, binary)
            
            try:   
                if binary[-1] == '1':
                    outputLine.append('Unit is malfunctioning')
                    self.state['critical'] += 1
            except IndexError:
                pass
            
            try:
                if binary[-2] == '1':
                    outputLine.append('AC Power not present')
                    self.state['critical'] += 1
            except IndexError:
                pass
               
            try: 
                numeral = self._convertBinarytoInteger(binary[-4:-2])
                
                if numeral == 1:
                    outputLine.append('Battery not fully charged')
                    self.state['warning'] += 1
                elif numeral == 2:
                    outputLine.append('Battery charge critically low') 
                    self.state['critical'] += 1
                elif numeral == 3:
                    outputLine.append('Battery completely drained')
                    self.state['critical'] += 1
                   
            except IndexError:
                pass          
                
            try:
                if binary[-7] == '1':
                    outputLine.append('UPS is off')
                    self.state['warning'] += 1
            except IndexError:
                pass
            
            try:
                if binary[-8] == '1':
                    outputLine.append('UPS is not present')
                    self.state['critical'] += 1
            except IndexError:
                pass
            
            self.output.append(' '.join(outputLine))           
        
        return None
    
    def __checkVoltageSensor(self, deviceDescription, status, sensorValue):
        '''
        For internal use, checks the voltage sensor. Expects a string for
        the deviceDescription, an integer for the status and an integer for
        the sensorValue.
        '''
        if status != 0:
            outputLine = []
            
            outputLine.append(deviceDescription + ':') # Begin our output line
                
            binary = self._convertIntegerToBinaryAndFormat(status)
            
            if self.verbose > 1:
                print ('Debug2: Device: {0}, Value:{1}, Status code:{2}'
                       'binary:{3}').format(deviceDescription, sensorValue, 
                                            status, binary)
            
            try:   
                if binary[-1] == '1':
                    outputLine.append('Voltage sensor is malfunctioning')
                    self.state['critical'] += 1
            except IndexError:
                pass
            
            try: 
                numeral = self._convertBinarytoInteger(binary[-4:-1])
            
                if numeral == 2:
                    outputLine.append('Low voltage warning')
                    self.state['warning'] += 1
                elif numeral == 3:
                    outputLine.append('High voltage warning') 
                    self.state['warning'] += 1
                elif numeral == 4:
                    outputLine.append('Low voltage limit exceeded')
                    self.state['critical'] += 1
                elif numeral == 5:
                    outputLine.append('High voltage limit exceeded')
                    self.state['critical'] += 1
            except IndexError:
                pass
            

                
            try:
                if binary[-7] == '1':
                    outputLine.append('Voltage sensor is not activated')
                    self.state['warning'] += 1
            except IndexError:
                pass
            
            try:
                if binary[-8] == '1':
                    outputLine.append('Voltage sensor is not present')
                    self.state['critical'] += 1
            except IndexError:
                pass
            
            self.output.append(' '.join(outputLine))           
        
        return None
        
    def checkDeviceStatus(self):
        '''
        Check the status of the RAID device and most associated components.
        This checks components like the CPU temperature, fan speed, sensor 
        temperatures, etc.
        
        This method expects no arguments.
        '''
        
        luDevTypeCodes = {1:(self.__checkPowerSupply), 
                          2:(self.__checkFan), 
                          3: self.__checkTempSensor,
                          4:(self.__checkUPS), 
                          5:(self.__checkVoltageSensor), 
                          6:(self.__checkCurrentSensor),
                          8:(self.__checkTempSensor),
                          9:(self.__checkDoor),
                          10:(self.__checkSpeaker), 
                          11:(self.__checkBattery),
                          17:(self.__checkSlotStates),
                          }
        
        # Description as a string
        luDevDescription = ('Logical unit device description:',
                            self.baseoid + '1.9.1.8', 'snmpwalk')
        # Type of device by code
        luDevType = ('Logical unit device type:',
                     self.baseoid + '1.9.1.6', 'snmpwalk')
        # Values of temps etc.
        luDevValue = ('Logical unit device value:', 
                      self.baseoid + '1.9.1.9', 'snmpwalk')
        # Status of devices
        luDevStatus = ('Logical unit device status:', 
                       self.baseoid + '1.9.1.13', 'snmpwalk')
        
        deviceDescription = self.__query(luDevDescription)[1]
        deviceType = self.__query(luDevType)[1]
        deviceValue = self.__query(luDevValue)[1]
        deviceStatus = self.__query(luDevStatus)[1]
                               
        for number, device in enumerate(deviceType):
            luDevTypeCodes[device](deviceDescription[number], 
                                   deviceStatus[number], deviceValue[number])
        return None
        
    def checkDriveStatus(self):
        '''
        Check the Hard Drive Status of the RAID and return the result.
        
        This method expects no arguments.
        
        This will check:
        Logical Disk Drive Count
        Logical Disk Spare Drive Count
        Logical Disk Failed Drive Count
        Logical Disk Status and parse the results for any error conditions
        Hard Drive Status and parse the results for any error conditions
        '''     
        
        ldTotalDrvCnt = ('Logical Drives:', self.baseoid + '1.2.1.8', 
                         'snmpwalk')
        ldSpareDrvCnt = ('Spare Drives:', self.baseoid + '1.2.1.10',
                         'snmpwalk')
        ldFailedDrvCnt = ('Failed Drives:', self.baseoid + '1.2.1.11', 
                          'snmpwalk')
        ldStatus = ('Logical Drive Status:', self.baseoid + '1.2.1.6',
                    'snmpwalk')
        hddStatus = ('Hard Drive Status:', self.baseoid + '1.6.1.11',
                     'snmpwalk')
        

        # Get the logical drive count 
        check, driveCount = self.__query(ldTotalDrvCnt)
        driveCount = ','.join(['%s' % element for element in driveCount])          
        self.output.append(check + driveCount)
        
        # Get the spare drive count
        check, spareCount = self.__query(ldSpareDrvCnt)
        spareCount = ','.join(['%s' % element for element in spareCount])
        self.output.append(check + spareCount)
        
        # Get the failed drive count
        check, failedCount = self.__query(ldFailedDrvCnt)
        failedCount = ','.join(['%s' % element for element in failedCount])
        self.output.append(check + failedCount)
        
        # Get the logical disk status
        check, logicalDriveStatus = self.__query(ldStatus)
        self.__checkLdStatus(logicalDriveStatus)
        
        # Get the status of the hard drives
        check, driveStatus =  self.__query(hddStatus)
        self.__checkHddStatus(driveStatus)
        
        if self.verbose > 1:
            print 'Debug2: Output from checkDriveStatus:', self.output
        
        return None
    
    def checkModelFirmware(self):
        '''
        Pull the system's make, model, serial number, firmware major and minor 
        numbers. Expects no arguments to be passed in.
        
        This method expects no arguments.
        '''
        
        privateLogoVendor = ('Vendor:', self.baseoid + '1.1.1.14.0', 'snmpget')
        privateLogoString = ('Model:', self.baseoid + '1.1.1.13.0', 'snmpget')
        serialNum = ('Serial Number:', self.baseoid + '1.1.1.10.0', 'snmpget')
        fwMajorVersion = ('Firmware Major Version:', 
                          self.baseoid + '1.1.1.4.0', 'snmpget')
        fwMinorVersion = ('Firmware Minor Version:', 
                          self.baseoid + '1.1.1.5.0', 'snmpget')
        
        # Get the vendor string
        check, vendor = self.__query(privateLogoVendor)   
        self.output.append(check + vendor)
        
        # Get the Manufacturers model
        check, model = self.__query(privateLogoString)
        self.output.append(check + model)
        
        # Get the serial number
        check, serialNumber = self.__query(serialNum)
        self.output.append('{0}{1}'.format(check, serialNumber))
        
        # Get the major and minor firmware versions
        check, firmwareMajor = self.__query(fwMajorVersion)
        check, firmwareMinor = self.__query(fwMinorVersion)
        self.output.append('Firmware Version:{0}.{1}'.format(firmwareMajor, 
                                                             firmwareMinor))
        
        if self.verbose > 1:
            print 'Debug2: Output from checkModelFirmware:', self.output
        
        return None
    
    def _convertBinarytoInteger(self, binary):
        '''
        Convert the given binary string to an integer. Appends 0b to the
        string before conversion.
        '''
        
        return int('0b' + binary, 2)
        
    def _convertIntegerToBinaryAndFormat(self, number):
        '''
        Convert the given integer to a number and removes the leading 0b
        and returns.
        '''
        return bin(number)[2:]
    
    def parsePrintExit(self):
        '''
        Parse the results, print the output and exit with the appropriate
        status.
        '''
        
        finalOutput = '{status}:{output}'
        
        if self.verbose > 1:
            print ('Debug2: Results passed to parsePrint: '
                   '{0} {1}').format(self.state, self.output)
        
        if self.state['critical']:
            status = 'CRITICAL'
        elif self.state['warning']:
            status = 'WARNING'
        elif self.state['unknown']:
            status = 'UNKNOWN'
        else:
            status = 'OK'
        
        finalLine = ''
        
        for line in self.output:
            finalLine += ' ' + line + ' ' 
        
        # Add in performance data if it exists
        if self.perfData:
            finalLine += '| '
            for line in self.perfData:
                finalLine += line + ' '
        
        # Construct and print our final output
        finalOutput = finalOutput.format(status = status, output = finalLine)
        print finalOutput
        
        sys.exit(eval(status))
        
        return None # Should never be reached
    
    def __query(self, items):
        '''
        For internal use, requires one input a tuple of items to be
        checked. That tuple must contain the following, a string defining
        the check in human readable terms, a string with the oid, and a
        string specifying the SNMP command to be run, usually snmpget or
        snmpwalk.
        '''
        
        check, oid, snmpCmd = items
        result = self.query(snmpCmd, oid)
        
        if self.verbose > 1:
            print 'Debug2:', check, result
        
        return check, result

def sigalarm_handler(signum, frame):
    '''
    Handler for an alarm situation.
    '''
    
    print '{0} timed out after {1} seconds'.format(sys.argv[0], 
                                                   options.timeout)
    print 'Debug: Exited with signum: {0}, frame: {1}'.format(signum, frame)
    
    sys.exit(CRITICAL)
    
if __name__ == '__main__':
    import optparse
    import signal
      
    parser = optparse.OptionParser(description='''Nagios plug-in to monitor
    Infortrend based RAIDs, this includes some Sun StorEdge RAIDs such 
    as the 3510 and the 3511.''', prog="check_infortrend", 
    version="%prog Version: 1.7")
    
    parser.add_option('-c', '--community', action='store', 
                      dest='community', type='string',default='public', 
                      help=('SNMP Community String to use. '
                      '(Default: %default)'))
    parser.add_option('-H', '--hostname', action='store', type='string', 
                      dest='hostname', default='localhost',
                      help='Specify hostname for SNMP (Default: %default)')
    parser.add_option('-t', '--timeout', dest='timeout', default=10,
                      help=('Set the timeout for the program to run '
                      '(Default: %default seconds)'), type='int')
    parser.add_option('-v', '--verbose', action='count', dest='verbose', 
                      default=0, help=('Give verbose output '
                      '(Default: Off)') )
    
    (options, args) = parser.parse_args()
    
    if options.verbose > 1:
        print 'Debug2: Options taken in:', options
        print 'Debug2: Arguments taken in:', args
        
    signal.signal(signal.SIGALRM, sigalarm_handler)
    
    signal.alarm(options.timeout)
    
    #Instantiate our object
    CHECK = CheckInfortrend(community = options.community, 
                        destHost = options.hostname, 
                        verbose = options.verbose)
    
    
    #This runs all of the checks
    CHECK.checkAll()
    
    signal.alarm(0)

        