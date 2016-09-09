#!/usr/bin/env python

'''
Nagios plugin to perform SNMP queries against Infortrend based RAIDs, this
includes Sun StorEdge 3510 and 3511 models. Parses the results and gives
an overall view of the health of the RAID.

Version: 2.2
Created: 2009-10-30
Author: Erinn Looney-Triggs
Revised: 2012-10-21
Revised by: Erinn Looney-Triggs, Jake Engleman, Eric Schoeller,
            Antoni Comerma Pare


License:
    check_infortrend, performs SNMP queries against Infortrend based RAIDS
    Copyright (C) 2012  Erinn Looney-Triggs

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
__version__ = 2.2
__status__ = 'Production'

# Nagios exit codes in English
UNKNOWN  = 3
CRITICAL = 2
WARNING  = 1
OK       = 0

blacklistoptions = {1:'power_supply',
                    2:'fan',
                    3:'temp_sensor',
                    4:'ups',
                    5:'voltage_sensor',
                    6:'current_sensor',
                    8:'temp_sensor',
                    9:'door',
                    10:'speaker',
                    11:'battery',
                    12:'led',
                    13:'cache_data_backup_flash_device',
                    14:'host_board',
                    15:'midplane_backplane',
                    17:'slot_states',
                    18:'enclosure_drawer',
                    31:'enclosure_management_services_controller',
                    99:'absent_drives'
                    }

class Snmp(object):
    '''
    A Basic Class for an SNMP session
    '''
    def __init__(self, version='2c', agent='localhost',
                 community='public', verbose=0):

        self.community = community
        self.agent = agent
        self.verbose = verbose
        self.version = version

    def query(self, snmp_command, oid):
        '''
        Creates an SNMP query session.

        snmpcmd is a required string that can either be 'snmpget'
        or 'snmpwalk'.

        oid is a required string that is the numerical OID to be used.
        '''

        full_snmp_command = self._which(snmp_command)

        if not full_snmp_command:
            print snmp_command, ('is not available in your path, or is not '
                                 'executable by you, exiting.')
            sys.exit(CRITICAL)

        command_line = ('%s -v %s -O v -c %s %s %s')

        command_line = command_line % (snmp_command, self.version,
                                       self.community, self.agent, oid,)

        if self.verbose > 1:
            print 'Debug2: Performing SNMP query:', command_line

        try:
            p = subprocess.Popen(command_line, shell=True,
                                 stdout = subprocess.PIPE,
                                 stderr = subprocess.STDOUT)
        except OSError:
            print 'Error:', sys.exc_info, 'exiting!'
            sys.exit(WARNING)

        # This is where we sanitize the output gathered.

        output = p.stdout.read().strip()

        if self.verbose > 1:
            print 'Debug2: Raw output obtained from query:', output

        return self._parse_snmp_output(snmp_command, output)

    def _parse_snmp_output(self, snmp_command, output):
        '''
        Parse the SNMP output and return values as integers or strings.
        Returns a list of items for walk and a single item for gets.

        Doctests Follow:
        >>> s = Snmp()

        Strings should be returned as strings.

        >>> s._parse_snmp_output('snmpget', 'STRING: "Notification"')
        'Notification'

        Strings with leading/trailing spaces should be returned minus
        quotes and spaces:

        >>> s._parse_snmp_output('snmpget', 'STRING: " Notification        "')
        'Notification'

        Integers should be returned as integers:

        >>> s._parse_snmp_output('snmpget', 'INTEGER: 0')
        0

        Other text/errors should be returned as strings:

        >>> s._parse_snmp_output('snmpget', ('No Such Object available on '
        ...                                  'this agent at this OID'))
        'No Such Object available on this agent at this OID'

        Walks of integers should return a list of integers:

        >>> s._parse_snmp_output('snmpwalk', 'INTEGER: 0\nINTEGER: 64')
        [0, 64]

        Walks of strings should return a list of strings:

        >>> s._parse_snmp_output('snmpwalk', ('STRING: "Any Source"\n'
        ...                                   'STRING: "Notification"'))
        ['Any Source', 'Notification']
        '''
        final_output = []

        for item in output.split('\n'):
            try:
                style, value = item.split(':')
            except ValueError:
                # If exception occurs this is probably a warning message
                # pass through.
                style = None
                value = item

            if style == 'INTEGER':
                final_output.append(int(value))
            elif style == 'STRING':
                # Strip whitespace, quotes, then whitespace again
                final_output.append(value.strip().strip('"').strip())
            else:
                # We treat any unknowns as strings
                final_output.append(value)

        if snmp_command == 'snmpget':
            final_output = final_output[0]

        if self.verbose > 1:
            print ('Debug2: Final output after cleaning:'
                   '%s') % (final_output)

        return final_output

    def _test(self):
        '''
        For internal use only, runs doctests against the module.
        '''
        import doctest
        doctest.testmod(verbose=True)

        return None

    def _which(self, program):
        '''
        This is the equivalent of the 'which' BASH built-in with a
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
    agent: a string giving the destination host as either an IP for FQDN
    verbose: a integer, any number other than zero will give you verbose output
    version: a string specifying the SNMP version to use only 1, and 2c are
    supported
    '''

    def __init__(self, blacklist, community='public', agent='localhost',
                 verbose=0, version='2c'):

        self.blacklist = self._parse_blacklist(blacklist)

        # Base OID found during auto detect
        self.base_oid = ''

        # Holder for state counts
        self.state = {'critical': 0, 'unknown': 0, 'warning': 0}

        # Holder for nagios output and perfdata output
        self.output = []
        self.perfData = []

        # Initialize our superclass
        Snmp.__init__(self, version, agent, community, verbose)

    def auto_detect(self):
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

        baseoids = ['1.3.6.1.4.1.1714.', '1.3.6.1.4.1.1714.1.',
                    '1.3.6.1.4.1.42.2.180.3510.1.',
                    '1.3.6.1.4.1.42.2.180.3510.1.',]

        for baseoid in baseoids:
            result = self.query('snmpget', baseoid + '1.1.1.10.0')

            if result != 'No Such Object available on this agent at this OID':
                self.base_oid = baseoid
                break

        if not self.base_oid:
            print ('Unable to auto detect array type at host: %s, '
                   'exiting.') % (self.agent)
            sys.exit(CRITICAL)

        if self.verbose > 1:
            print 'Debug 2: Base OID set to:', self.base_oid

        return None

    def check_all(self):
        '''
        Convenience method that will run all of the checks against the
        RAID.

        This method expects no arguments.
        '''

        self.auto_detect()
        self.check_model_firmware()
        self.check_drive_status()
        self.check_device_status()
        self.parse_print_exit()

        return None

    def _check_battery(self, deviceDescription, status, sensorValue, sensorValueUnit):
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

            if self.verbose > 0:
                print ('Debug1: Device:%s, Value:%s, Status code:%s '
                       'binary:%s') % (deviceDescription, sensorValue,
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
            except IndexError:
                pass

            try:
                numeral = self._convertBinarytoInteger(binary[-4:-2])

                if numeral == 1:
                    outputLine.append('Battery not fully charged')
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

    def _check_cache_data_backup_flash_device(self, deviceDescription, status, sensorValue, sensorValueUnit):
        '''
          Cache-Data-Backup Flash Device:
             BIT 0 - CLEAR:  Flash Device functioning normally.
                     SET:    Flash Device malfunctioning.
             BITS 1-5 - Reserved (Set to 0).
             BIT 6 - CLEAR:  Flash Device is enabled.
                     SET:    Flash Device is disabled.
             BIT 7 - CLEAR:  Flash Device IS present.
                     SET:    Flash Device is NOT present.
             == 0xff - Status unknown.
        '''
        # If status is 0 everything is copacetic
        if status != 0:
            outputLine = []

            outputLine.append(deviceDescription + ':') # Begin our output line

            binary = self._convertIntegerToBinaryAndFormat(status)

            if self.verbose > 0:
                print ('Debug1: Device:%s, Value:%s, Status code:%s '
                       'binary:%s') % (deviceDescription, sensorValue,
                                            status, binary)
            try:
                if binary[-1] == '1':
                    outputLine.append('Flash Device malfunctioning')
                    self.state['critical'] += 1
            except IndexError:
                pass

            self.output.append(' '.join(outputLine))

        return None


    def _check_current_sensor(self, deviceDescription, status, sensorValue, sensorValueUnit):
        '''
        For internal use, checks the current sensor status. Expects a
        string for the deviceDescription, an integer for the status and
        an integer for the sensorValue.
        '''

        if status != 0:
            outputLine = []

            outputLine.append(deviceDescription + ':') # Begin our output line

            binary = self._convertIntegerToBinaryAndFormat(status)

            if self.verbose > 0:
                print ('Debug1: Device:%s, Value:%s, Status code:%s '
                       'binary:%s') % (deviceDescription, sensorValue,
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

    def _check_door(self, deviceDescription, status, sensorValue, sensorValueUnit):
        '''
        For internal use, checks the current sensor status. Expects a
        string for the deviceDescription, an integer for the status and
        an integer for the sensorValue.
        '''

        if status != 0:
            outputLine = []

            outputLine.append(deviceDescription + ':') # Begin our output line

            binary = self._convertIntegerToBinaryAndFormat(status)

            if self.verbose > 0:
                print ('Debug1: Device:%s, Value:%s, Status code:%s '
                       'binary:%s') % (deviceDescription, sensorValue,
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


    def _check_fan(self, deviceDescription, status, sensorValue, sensorValueUnit):
        '''
        For internal use, checks the fan status. Expects a string
        for the deviceDescription, an integer for the status an
        integer for the sensorValue.

        Depending on the device model, we could get:
        a) The real speed (rpm). Easy
        b) A value that must be converted to rpm using the following table
        Conversions for fan speed:
        12292 < 4000 rpm
        77828 = 4000 - 4285 rpm
        143364 = 4286 - 4570 rpm
        208900 = 4571 - 4856 rpm
        274436 = 4857 - 5142 rpm
        339972 = 5143 - 5428 rpm
        405508 = 5429 - 5713 rpm
        471044 > 5713 rpm
        c) A "relative" speed
            From IFT_MIB.txt
             Fan (RPM):
                if luDevValue>0 and luDevValueUnit>0, the readable value = luDevValue
                else if luDevValueUnit == 0
                    luDevValue = 0, means the FAN is in `Normal`
                    luDevValue = 1, means the FAN is in `Lowest speed`
                    luDevValue = 2, means the FAN is in `Second lowest speed`
                    luDevValue = 3, means the FAN is in `Third lowest speed`
                    luDevValue = 4, means the FAN is in `Intermediate speed`
                    luDevValue = 5, means the FAN is in `Third highest speed`
                    luDevValue = 6, means the FAN is in `Second highest speed`
                    luDevValue = 7, means the FAN is in `Highest speed`
            In this scenario, we translate this value to rpm using the table from
            b). Not accurate, but serves to have homogeneus values.
        '''

        #Infortrend decided to do mappings from certain numbers to fan speeds
        #Why they couldn't just output the speed is beyond me, but I don't do
        #hardware design so maybe there is a good reason.
        fanSpeedsOld = {0:0,           #Indicates fan speed is not available.
                     12292:4000,
                     77828:4285,
                     143364:4570,
                     208900:4571,
                     274436:4857,
                     339972:5428,
                     405508:5713,
                     471044:5800,
                     }
        fanSpeedsNew = {1:4000,
                     2:4285,
                     3:4570,
                     0:4571,
                     4:4857,
                     5:5428,
                     6:5713,
                     7:5800,
                     }
        # Printing fan speed

        #Sometimes the value is ludicrously large
        if sensorValue > 0xffff:
            sensorValue &= 0x0000ffff

        # If value higher to max rpm, then user fanSpeedsOld table
        if sensorValue > 10000:
            fanSpeed = fanSpeedsOld[sensorValue]
        elif sensorValueUnit == 0 or sensorValueUnit == -1:
            # Speed according to fanSpeedsNew table
            fanSpeed = fanSpeedsNew[sensorValue]
        elif sensorValueUnit == 1:
            # Speed should be in sensorValue
            fanSpeed = sensorValue
        else:
            # Never should reach this code....
            fanSpeed=0

        warnRPM = '5713'
        critRPM = '5800'
        minRPM = '0'
        maxRPM = '6000'

        if self.verbose > 0:
            print 'Debug1: Fan speed is:%s rpm.'% (fanSpeed)

        self.perfData.append("'%s'=%s;%s;%s;%s;%s"
                             % (deviceDescription,
                                fanSpeed, warnRPM,
                                critRPM, minRPM, maxRPM))

        outputLine = []
        outputLine.append(deviceDescription + ':') #Begin our output line

        if status != 0:

            binary = self._convertIntegerToBinaryAndFormat(status)

            if self.verbose > 0:
                print ('Debug1: Device:%s, Value:%s, Status code:%s '
                       'binary:%s') % (deviceDescription, sensorValue,
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

        # If fan speed is high, raise a warning or critical
        if fanSpeed >= critRPM:
            outputLine.append('Fan speed is >= ' + str(critRPM))
            self.state['critical'] += 1
            self.output.append(' '.join(outputLine))
        elif fanSpeed >= warnRPM:
            outputLine.append('Fan speed is >= ' + str(warnRPM))
            self.state['warning'] += 1
            self.output.append(' '.join(outputLine))

        return None

    def _check_generic_device(self, deviceDescription, status, sensorValue, sensorValueUnit):
        '''
            Check used for generic devices where we just want an OK/KO
            For instance:
             - Enclosure Management Services Controller
             - Host Board
             - Midplane / backplane
             - Enclosure Drawer
        '''

        # If status is 0 everything is copacetic
        if status != 0:
            outputLine = []

            outputLine.append(deviceDescription + ':') # Begin our output line

            binary = self._convertIntegerToBinaryAndFormat(status)

            if self.verbose > 0:
                print ('Debug1: Device:%s, Value:%s, Status code:%s '
                       'binary:%s') % (deviceDescription, sensorValue,
                                            status, binary)
            try:
                if binary[-1] == '1':
                    outputLine.append(deviceDescription + ' malfunctioning')
                    self.state['critical'] += 1
            except IndexError:
                pass

            self.output.append(' '.join(outputLine))

        return None


    def _check_hdd_model_serial_number(self, hdd):
        '''
        For internal use, grabs the model and serial number for the d
        rive number that is passed in and appends it to the nagios output.
        This is designed to be used when a failed drive is detected,
        the model and serial number is grabbed for convenience.
        It can however, be used for other purposes. Takes one argument hdd
        which is an int of the drive you wish to check.
        '''
        hddModel = ('Hard Drive Model:',
                    self.base_oid + '1.6.1.15.' + str(hdd), 'snmpget')
        hddSerialNum = ('Hard Drive Serial Number:',
                        self.base_oid + '1.6.1.17.' + str(hdd),
                        'snmpget')

        model = self._query(hddModel)[1]
        self.output.append('model:%s' % (model))
        serialNumber = self._query(hddSerialNum)[1]
        self.output.append('serial number:%s' % (serialNumber))


        return None

    def _check_hdd_status(self, hdds):
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
            if self.verbose > 0:
                print 'Debug1: checking drive:', drive, 'with status:', status

            # Drive Absent is something blacklistable. Check it
            if status == 63 and self.blacklist.count('absent_drives'):
                continue

            if status in criticalCodes:
                self.state['critical'] += 1
                self.output.append('Drive ' + str(drive + 1) + ': '
                                + criticalCodes[status])

                # Grab the serial if the drive has failed, for lazy admins
                if status == 255 or status == 63:
                    self._check_hdd_model_serial_number(drive + 1)

            elif status in warningCodes:
                self.state['warning'] += 1
                self.output.append('Drive ' + str(drive + 1) + ': '
                                + warningCodes[status])

        return None


    def _check_ld_status(self, logicalDrives):
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
                         128:'Logical Drive Off-line'
                         }

        for drive, status in enumerate(logicalDrives):
            if self.verbose > 0:
                print ('Debug1: Checking logical drive: '
                       '%s with status: %s') % (drive, status)

            if status in criticalCodes:
                self.state['critical'] += 1
                self.output.append('Logical Drive ' + str(drive + 1) + ': '
                            + criticalCodes[int(status)])

            elif int(status) in warningCodes:
                self.state['warning'] += 1
                self.output.append('Logical Drive ' + str(drive + 1) + ': '
                                + warningCodes[int(status)])

        return None

    def _check_led(self, deviceDescription, status, sensorValue, sensorValueUnit):
        '''
            Check led status.
            ** Even if led is active, don't raise a warning. It's too common.
                 LED:
                     BITS 0-5 - Reserved (Set to 0).
                     BIT 6 - CLEAR:  LED is active
                             SET:    LED is inactive
                     BIT 7 - CLEAR:  LED IS present.
                             SET:    LED is NOT present.
                     == 0xff - Status unknown.
        '''

        # If status is 0 everything is copacetic
        if status != 0:
            outputLine = []

            outputLine.append(deviceDescription + ':') # Begin our output line

            binary = self._convertIntegerToBinaryAndFormat(status)

            if self.verbose > 0:
                print ('Debug1: Device:%s, Value:%s, Status code:%s '
                       'binary:%s') % (deviceDescription, sensorValue,
                                            status, binary)
            try:
                if binary[-7] == '1':
                    outputLine.append('ON')
            except IndexError:
                pass

            self.output.append(' '.join(outputLine))

        return None


    def _check_null(self, deviceDescription, status, sensorValue, sensorValueUnit):
        '''
        This is the dumping ground for unknown hardware entries. This sadly
        seems to come about because Infortrend is not documenting all modules
        in their MIB files. Any entries pointed here will return nothing.
        '''

        return None

    def _check_power_supply(self, deviceDescription, status, sensorValue, sensorValueUnit):
        '''
        For internal use, checks the Power supply status. Expects a string
        for the deviceDescription, an integer for the status and an
        integer for the sensorValue.
        '''

        if status != 0:
            outputLine = []

            outputLine.append(deviceDescription + ':') #Begin our output line

            binary = self._convertIntegerToBinaryAndFormat(status)

            if self.verbose > 0:
                print ('Debug1: Device:%s, Value:%s, Status code:%s '
                       'binary:%s') % (deviceDescription, sensorValue,
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

    def _check_speaker(self, deviceDescription, status, sensorValue, sensorValueUnit):
        '''
        For internal use, checks the speaker status. Expects a
        string for the deviceDescription, an integer for the status and
        an integer for the sensorValue.
        '''

        if status != 0:
            outputLine = []

            outputLine.append(deviceDescription + ':') # Begin our output line

            binary = self._convertIntegerToBinaryAndFormat(status)

            if self.verbose > 0:
                print ('Debug1: Device:%s, Value:%s, Status code:%s '
                       'binary:%s') % (deviceDescription, sensorValue,
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

    def _check_slot_states(self, deviceDescription, status, sensorValue, sensorValueUnit):
        '''
        For internal use, checks the slot status. Expects a
        string for the deviceDescription, an integer for the status and
        an integer for the sensorValue.
        '''

        if status != 0:
            outputLine = []

            outputLine.append(deviceDescription + ':') # Begin our output line

            binary = self._convertIntegerToBinaryAndFormat(status)

            if self.verbose > 0:
                print ('Debug1: Device:%s, Value:%s, Status code:%s '
                       'binary:%s') % (deviceDescription, sensorValue,
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

    def _check_temp_sensor(self, deviceDescription, status, sensorValue, sensorValueUnit):
        '''
        For internal use, checks the temperature sensor and returns the
        value as perfdata to be used by nagios. Expects a string for
        the deviceDescription, an integer for the status and an integer for
        the sensorValue.
        According to MIB:
            Temperature Sensor: the readable value = (luDevValue * luDevValueUnit / 1000) - 273
        but... some old devices doesnt follow de rule. I've made a guess shifting the value 16 bits right.
        '''
        #Sometimes the value is ludicrously large
        if sensorValue > 0xffff:
            sensorValue >>= 16

        #Some devices report a temperature of 0
        if sensorValue == 0:
            temperature = sensorValue
        else:
            # Temperature is in Celsius
            temperature = (sensorValue * sensorValueUnit / 1000) - 273

        warnTemp = '70'
        critTemp = '80'
        minTemp = '0'
        maxTemp = '100'

        self.perfData.append("'%s'=%s;%s;%s;%s;%s"
                             % (deviceDescription, temperature, warnTemp,
                                     critTemp, minTemp, maxTemp))

        # If status is 0 everything is copacetic
        if status != 0:
            outputLine = []

            outputLine.append(deviceDescription + ':') #Begin our output line

            binary = self._convertIntegerToBinaryAndFormat(status)

            if self.verbose > 0:
                print ('Debug1: Device:%s, Value:%s, Status code:%s '
                       'binary:%s') % (deviceDescription, sensorValue,
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

    def _check_ups(self, deviceDescription, status, sensorValue, sensorValueUnit):
        '''
        For internal use, checks the UPS status. Expects a string for
        the deviceDescription, an integer for the status and an integer for
        the sensorValue.
        '''
        #When the status is 255, state is unknown and we ignore
        if status == 255:
            return None

        elif status != 0:
            outputLine = []

            outputLine.append(deviceDescription + ':') #Begin our output line

            binary = self._convertIntegerToBinaryAndFormat(status)

            if self.verbose > 0:
                print ('Debug1: Device:%s, Value:%s, Status code:%s '
                       'binary:%s') % (deviceDescription, sensorValue,
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

    def _check_voltage_sensor(self, deviceDescription, status, sensorValue, sensorValueUnit):
        '''
        For internal use, checks the voltage sensor. Expects a string for
        the deviceDescription, an integer for the status and an integer for
        the sensorValue.
        '''
        if status != 0:
            outputLine = []

            outputLine.append(deviceDescription + ':') # Begin our output line

            binary = self._convertIntegerToBinaryAndFormat(status)

            if self.verbose > 0:
                print ('Debug1: Device:%s, Value:%s, Status code:%s'
                       'binary:%s') % (deviceDescription, sensorValue,
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

    def check_device_status(self):
        '''
        Check the status of the RAID device and most associated components.
        This checks components like the CPU temperature, fan speed, sensor
        temperatures, etc.

        This method expects no arguments.
        '''

        luDevTypeCodes = {1:(self._check_power_supply),
                          2:(self._check_fan),
                          3:(self._check_temp_sensor),
                          4:(self._check_ups),
                          5:(self._check_voltage_sensor),
                          6:(self._check_current_sensor),
                          8:(self._check_temp_sensor),
                          9:(self._check_door),
                          10:(self._check_speaker),
                          11:(self._check_battery),
                          12:(self._check_led),
                          13:(self._check_cache_data_backup_flash_device),
                          14:(self._check_generic_device),
                          15:(self._check_null),
                          17:(self._check_slot_states),
                          18:(self._check_generic_device),
                          31:(self._check_generic_device),
                          }

        # Description as a string
        luDevDescription = ('Logical unit device description:',
                            self.base_oid + '1.9.1.8', 'snmpwalk')
        # Type of device by code
        luDevType = ('Logical unit device type:',
                     self.base_oid + '1.9.1.6', 'snmpwalk')
        # Values of temps etc.
        luDevValue = ('Logical unit device value:',
                      self.base_oid + '1.9.1.9', 'snmpwalk')
        # Logical unit device value unit.
        luDevValueUnit = ('Logical unit device value unit:',
                      self.base_oid + '1.9.1.10', 'snmpwalk')
        # Status of devices
        luDevStatus = ('Logical unit device status:',
                       self.base_oid + '1.9.1.13', 'snmpwalk')

        deviceDescription = self._query(luDevDescription)[1]
        deviceType = self._query(luDevType)[1]
        deviceValue = self._query(luDevValue)[1]
        deviceValueUnit = self._query(luDevValueUnit)[1]
        deviceStatus = self._query(luDevStatus)[1]

        for number, device in enumerate(deviceType):
            if  not self.blacklist.count(blacklistoptions[device]):
                luDevTypeCodes[device](deviceDescription[number],
                                        deviceStatus[number],
                                        deviceValue[number],
                                        deviceValueUnit[number])
            else:
                if self.verbose > 0:
                    print 'Debug1: Device blacklisted ->', blacklistoptions[device]
        return None

    def check_drive_status(self):
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

        ldTotalDrvCnt = ('Logical Drives:', self.base_oid + '1.2.1.8',
                         'snmpwalk')
        ldSpareDrvCnt = ('Spare Drives:', self.base_oid + '1.2.1.10',
                         'snmpwalk')
        ldFailedDrvCnt = ('Failed Drives:', self.base_oid + '1.2.1.11',
                          'snmpwalk')
        ldStatus = ('Logical Drive Status:', self.base_oid + '1.2.1.6',
                    'snmpwalk')
        hddStatus = ('Hard Drive Status:', self.base_oid + '1.6.1.11',
                     'snmpwalk')


        # Get the logical drive count
        check, driveCount = self._query(ldTotalDrvCnt)
        driveCount = ','.join(['%s' % element for element in driveCount])
        self.output.append(check + driveCount)

        # Get the spare drive count
        check, spareCount = self._query(ldSpareDrvCnt)
        spareCount = ','.join(['%s' % element for element in spareCount])
        self.output.append(check + spareCount)

        # Get the failed drive count
        check, failedCount = self._query(ldFailedDrvCnt)
        failedCount = ','.join(['%s' % element for element in failedCount])
        self.output.append(check + failedCount)

        # Get the logical disk status
        check, logicalDriveStatus = self._query(ldStatus)
        self._check_ld_status(logicalDriveStatus)

        # Get the status of the hard drives
        check, driveStatus =  self._query(hddStatus)
        self._check_hdd_status(driveStatus)

        if self.verbose > 0:
            print 'Debug1: Output from checkDriveStatus:', self.output

        return None

    def check_model_firmware(self):
        '''
        Pull the system's make, model, serial number, firmware major and minor
        numbers. Expects no arguments to be passed in.

        This method expects no arguments.
        '''

        privateLogoVendor = ('Vendor:',
                             self.base_oid + '1.1.1.14.0', 'snmpget')
        privateLogoString = ('Model:',
                             self.base_oid + '1.1.1.13.0', 'snmpget')
        serialNum = ('Serial Number:',
                     self.base_oid + '1.1.1.10.0', 'snmpget')
        fwMajorVersion = ('Firmware Major Version:',
                          self.base_oid + '1.1.1.4.0', 'snmpget')
        fwMinorVersion = ('Firmware Minor Version:',
                          self.base_oid + '1.1.1.5.0', 'snmpget')

        # Get the vendor string
        check, vendor = self._query(privateLogoVendor)
        self.output.append(check + vendor)

        # Get the Manufacturers model
        check, model = self._query(privateLogoString)
        self.output.append(check + model)

        # Get the serial number
        check, serialNumber = self._query(serialNum)
        self.output.append('%s %s' % (check, serialNumber))

        # Get the major and minor firmware versions
        check, firmwareMajor = self._query(fwMajorVersion)
        check, firmwareMinor = self._query(fwMinorVersion)
        self.output.append('Firmware Version:%s.%s' % (firmwareMajor,
                                                       firmwareMinor))

        if self.verbose > 0:
            print 'Debug1: Output from checkModelFirmware:', self.output

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

    def _parse_blacklist(self, blacklist):
        '''
        Split the blacklist on '/' and return a list.

        This method expects one argument:
        blacklist: a string.
        '''
        if blacklist:
            return (blacklist.lower()).split('/')
        else:
            return []

    def parse_print_exit(self):
        '''
        Parse the results, print the output and exit with the appropriate
        status.
        '''

        finalOutput = '%s:%s'

        if self.verbose > 0:
            print ('Debug1: Results passed to parsePrint: '
                   '%s %s') % (self.state, self.output)

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
        finalOutput = finalOutput % (status, finalLine)
        print finalOutput

        sys.exit(eval(status))

        return None # Should never be reached

    def _query(self, items):
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

#    def _test(self):
#        '''
#        For internal use, runs doctests against the module.
#        '''
#        import doctest
#        doctest.testmod()
#
#        return None

def sigalarm_handler(signum, frame):
    '''
    Handler for an alarm situation.
    '''

    print ('%s timed out after %s seconds, '
           'signum:%s, frame: %s') % (sys.argv[0], options.timeout,
                                      signum, frame)

    sys.exit(CRITICAL)

if __name__ == '__main__':
    import optparse
    import signal
    blacklist_help=''


    parser = optparse.OptionParser(description='''Nagios plug-in to monitor
    Infortrend based RAIDs, this includes some Sun StorEdge RAIDs such
    as the 3510 and the 3511.''', prog="check_infortrend",
    version="%prog Version: 2.2")
    for i,j in blacklistoptions.iteritems():
        blacklist_help=blacklist_help + j + ' '
    parser.add_option('-b', '--blacklist', action='store', dest='blacklist',
                      type='string', default=None,
                      help=('Checks to blacklist.Use "/" as delimitator (Default: %default) Options:'+blacklist_help))
    parser.add_option('-c', '--community', action='store',
                      dest='community', type='string', default='public',
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

    if options.verbose > 0:
        print 'Debug1: Options taken in:', options
        print 'Debug1: Arguments taken in:', args

    signal.signal(signal.SIGALRM, sigalarm_handler)

    signal.alarm(options.timeout)

    #Instantiate our object
    CHECK = CheckInfortrend(blacklist=options.blacklist,
                            community = options.community,
                            agent = options.hostname,
                            verbose = options.verbose )

    #This runs all of the checks
    CHECK.check_all()

    signal.alarm(0)
