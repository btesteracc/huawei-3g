import requests
import xmltodict
import time
from datetime import datetime
import netifaces
import queue
import logging
import logging.handlers
from pprint import pformat
import argparse
try:
    from huawei_3g.datastructures import SMSMessage
except ModuleNotFoundError:
    from datastructures import SMSMessage


class TokenError(Exception):
    pass


class HuaweiModem:
    """ This class abstracts the communication with a
    Huawei HiLink E303, E3372, E3531 ... modem"""
    token = ""

    _error_codes = {
        "100002": "No support",  # Huawei branded 404
        "100003": "Access denied",  # Huawei branded 403
        "100004": "Busy",
        "108001": "Wrong username",
        "108002": "Wrong password",
        "108003": "Already logged in",
        "120001": "Voice busy",
        "125001": "Wrong __RequestVerificationToken header",
        "125002": "Token Error",
        "125003": "No valid Token"
    }
    _network_type = {
        0: "No service",
        1: "GSM",
        2: "GPRS",
        3: "EDGE",
        4: "WCDMA",
        5: "HSDPA",
        6: "HSUPA",
        7: "HSPA",
        8: "TDSCDMA",
        9: "HSPA+",
        10: "EVDO rev 0",
        11: "EVDO rev A",
        12: "EVDO rev B",
        13: "1xRTT",
        14: "UMB",
        15: "1xEVDV",
        16: "3xRTT",
        17: "HSPA+ 64QAM",
        18: "HSPA+ MIMO",
        19: "LTE",
        41: "3G"
    }
    _network_status = {
        2: "Connection failed, the profile is invalid",
        3: "Connection failed, the profile is invalid",
        5: "Connection failed, the profile is invalid",
        7: "Network access not allowed",
        8: "Connection failed, the profile is invalid",
        11: "Network access not allowed",
        12: "Connection failed, roaming not allowed",
        13: "Connection failed, roaming not allowed",
        14: "Network access not allowed",
        20: "Connection failed, the profile is invalid",
        21: "Connection failed, the profile is invalid",
        23: "Connection failed, the profile is invalid",
        27: "Connection failed, the profile is invalid",
        28: "Connection failed, the profile is invalid",
        29: "Connection failed, the profile is invalid",
        30: "Connection failed, the profile is invalid",
        31: "Connection failed, the profile is invalid",
        32: "Connection failed, the profile is invalid",
        33: "Connection failed, the profile is invalid",
        37: "Network access not allowed",
        113: "Network status 113",
        201: "Connection failed, bandwidth exceeded",
        900: "Connecting",
        901: "Connected",
        902: "Disconnected",
        903: "Disconnecting",
        905: "Connection failed, signal poor",
    }

    def __init__(self, interface, sysfs_path, log=None, logLevel=logging.INFO):
        """ Create instance of the HuaweiModem class

        :param interface: Name of the network interface associated with this modem
        :param sysfs_path: The path in /sys/** that represents this USB device
        :param log object: if none, a default object will be used
        :param logLevel default to INFO
        """
        self.interface = interface
        gws = netifaces.gateways()
        for nettpl in gws[netifaces.AF_INET]:
            if nettpl[1] == interface:
                ip = nettpl[0]
                break
        self.path = sysfs_path
        self.ip = ip
        self._base_url = "http://{}/api".format(self.ip)
        self.token = ""
        self._headers = None
        if log is None:
            logger = logging.getLogger(u'HuaweiModem')
            logger.setLevel(logLevel)
            handler = logging.StreamHandler()
            logger.addHandler(handler)
            self._log = logger
        else:
            self._log = logger

        self._infos = {}
        try:
            self._infos = self.get_device_infos()
        except TokenError:
            self._get_token_ext()
            self._infos = self.get_device_infos()
        if u'DeviceName' in self._infos.keys():
            pass
        else:
            # modele type E3372
            self._devicename = u'E3372'
        self._log.debug(u'{}'.format(self._infos))
        # self._get_token()

    def get_device_infos(self):
        status_raw = self._api_get("/device/information")
        return(status_raw)

    @property
    def status(self):
        return self.get_status()

    def get_status(self):
        """ Get the status of the attached modem

        This returns the status/connection information of this modem as a dictionary with the following keys:

        status
          The current status as a string. Mostly "Connected" or "Disconnected" but also might contain an error
          message if the connection is unsuccessful

        signal
          The signal strength of the modem as a int representing a percentage

        network_type
          The protocol used to communicate with the network. Ex: 3G or GPRS
        """
        status_raw = self._api_get("/monitoring/status")
        signal = int(int(status_raw['SignalIcon']) / 5.0 * 100.0)
        network_type = "Unknown"
        if int(status_raw['CurrentNetworkType']) in self._network_type:
            network_type = self._network_type[int(status_raw['CurrentNetworkType'])]
        return {
            'status': self._network_status[int(status_raw['ConnectionStatus'])],
            'signal': signal,
            'network_type': network_type
        }

    @property
    def message_count(self):
        return self.get_message_count()

    def get_message_count(self):
        """ Get the amount of SMS messages on the modem

        Returns the amount of SMS messages stored on the internal memory of the modem as a dictionary

        count
          The total amount of messages on the modem

        unread
          The count of messages that arent read yet.
        """
        messages_raw = self._api_get("/sms/sms-count")
        return {
            'count': int(messages_raw['LocalInbox']),
            'siminbox': int(messages_raw['SimInbox']),
            'simoutbox': int(messages_raw['SimOutbox']),
            'newmsg': int(messages_raw['NewMsg']),
            'unread': int(messages_raw['LocalUnread']),
            'simunread': int(messages_raw['SimUnread']),
            'deleted': int(messages_raw['LocalDeleted']),
            'localmax': int(messages_raw['LocalMax']),
            'simmax': int(messages_raw['SimMax']),
            'simdraft': int(messages_raw['SimDraft']),
            'localdraft': int(messages_raw['LocalDraft']),
            'outbox': int(messages_raw['LocalOutbox'])
        }

    @property
    def in_messages(self):
        return self.get_messages(delete=False, boxType=1)

    @property
    def out_messages(self):
        return self.get_messages(delete=False, boxType=2)

    def get_messages(self, delete=False, boxType=1):
        """ Get all SMS messages stored on the modem

        This receives all SMS messages that are on the internal memory of the modem as
        :class:`~huawei_3g.datastructures.SMSMessage` instances.

        If you set the delete argument to True then the messages will be deleted after retrieving them with this method.

        :param delete: Delete the messages after this call
        """
        raw = self._api_post("/sms/sms-list",
                             "<?xml version=\"1.0\" encoding=\"UTF-8\"?><request>"
                             "<PageIndex>1</PageIndex>"
                             "<ReadCount>50</ReadCount>"
                             "<BoxType>{}</BoxType>"
                             "<SortType>0</SortType>"
                             "<Ascending>0</Ascending>"
                             "<UnreadPreferred>0</UnreadPreferred>"
                             "</request>".format(boxType))
        messages = []
        if raw['Count'] == '0':
            return []

        if raw['Count'] == '1':
            message_list = [raw['Messages']['Message']]
        else:
            message_list = raw['Messages']['Message']

        for message in message_list:
            sms = SMSMessage()
            sms.message_id = message['Index']
            sms.message = message['Content']
            sms.phone = message['Phone']
            if boxType == 2:
                sms.phone = message['Phone']
                sms.dest = message['Phone']
                send_time = message['Date']
                sms.send_time = datetime.strptime(send_time, '%Y-%m-%d %H:%M:%S')
                sms.rs_time = sms.send_time
                sms.priority = message['Priority']
            else:
                sms.phone = message['Phone']
                sms.sender = message['Phone']
                receive_time = message['Date']
                sms.receive_time = datetime.strptime(receive_time, '%Y-%m-%d %H:%M:%S')
                sms.rs_time = sms.receive_time
            messages.append(sms)
        if delete:
            ids = []
            for message in messages:
                ids.append(message.message_id)
            self.delete_messages(ids)
        return messages

    def delete_message(self, message_id):
        """ Delete a SMS message from the modem

        This removes a message from the modem by message index. The message index is found in
        the :class:`~huawei_3g.datastructures.SMSMessage` instance returned
        by :func:`~huawei_3g.HuaweiModem.get_messages`
        """
        return self.delete_messages([message_id])

    def delete_messages(self, ids):
        """ Delete multiple SMS messages from the modem

        This does the same thing as :func:`~huawei_3g.HuaweiModem.delete_message` but accepts a list of message
        indexes to delete them in a single API call.
        """
        xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><request>"
        for message_id in ids:
            xml += "<Index>{}</Index>".format(message_id)
        xml += "</request>"
        self._api_post("/sms/delete-sms", xml)

    def send_sms(self, numbers, message):
        """ send sms to a list of number

        :param numbers: array of phone number
        :param text to send
        """
        """ Added 04th june 2017 by Bjoern"""
        """ Updated 01th febr 2020 by Afer92"""
        phones = u''
        if type(numbers) == str:
            numbers = numbers.split(u',')
        for number in numbers:
            phones += u'<Phone>{}</Phone>'.format(number)
        mxml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><request><Index>-1</Index>"
        mxml += "<Phones>{}</Phones><Sca/>".format(phones)
        mxml += "<Content>{}</Content>".format(message)
        mxml += "<Length>{}</Length><Reserved>1</Reserved>".format(len(message))
        mxml += "<Date>{}</Date></request>".format(datetime.strftime(datetime.now(),
                                                   '%Y-%m-%d %H:%M:%S'))
        self.log.debug(mxml)
        self._api_post("/sms/send-sms", mxml)

    def connect(self):
        xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><request><Action>1</Action></request>"
        self._api_post("/dialup/dial", xml)

    def disconnect(self):
        xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><request><Action>0</Action></request>"
        self._api_post("/dialup/dial", xml)

    def __repr__(self):
        part0 = u'<HuaweiModem {} ({})>'.format(self.interface, self.path)
        part1 = u'\nDeviceName     : %s\nimei           : %s\nimsi           : %s\n' %\
                (self.deviceName, self.imei, self.imsi)
        part2 = u'iccid          : %s\nmsisdn         : %s\n' %\
                (self.iccid, self.msisdn)
        part3 = u'SerialNumber   : %s\nsoftwareVersion: %s\nhardwareVersion: %s\n' %\
                (self.serialNumber, self.softwareVersion, self.hardwareVersion)
        part4 = u'MacAddress1    : %s\nWebUIVersion   : %s\n' % (self.macAddress1, self.webUIVersion)
        part5 = u'ProductFamily  : %s\nclassify       : %s\n' %\
                (self.productFamily, self.classify)
        part6 = u'supportmode    : %s\nworkmode       : %s\n' %\
                (self.supportmode, self.workmode)
        return part0 + part1 + part2 + part3 + part4 + part5 + part6

    def _get_token(self):
        token_response = self._api_get("/webserver/token")
        self.token = token_response['token']

    def _get_token_ext(self):
        log = self._log
        token_raw = self._api_get("/webserver/SesTokInfo")
        if token_raw != {}:
            if u'error' in token_raw:
                log.debug(u'error: %s' % (token_raw[u'error']))
            else:
                log.debug(u'token_raw: %s' % (token_raw))
                log.debug(u'tokinfo: %s' % (token_raw[u'TokInfo']))
                log.debug(u'sesinfo: %s' % (token_raw[u'SesInfo']))
                log.debug(u'sessionid: %s' % (token_raw[u'SesInfo'].split(u'=')[1]))
                self.token = token_raw[u'TokInfo']
                self.cookie = token_raw[u'SesInfo'].split(u'=')[1]

    def _api_request_token(self, url, rtype=u'GET', parameters=None):
        if rtype == u'POST':
            response = requests.post(url,
                                     parameters,
                                     headers={
                                              "__RequestVerificationToken": self.token
                                              },
                                     cookies={u'SessionId': self.cookie}
                                     )
        elif rtype == u'GET':
            response = requests.get(url,
                                    parameters,
                                    headers={
                                             "__RequestVerificationToken": self.token
                                            },
                                    cookies={u'SessionId': self.cookie}
                                    )
        return response

    def _api_request_base(self, url, rtype=u'GET', parameters=None):
        if rtype == u'POST':
            response = requests.post(url, parameters, headers={
                "__RequestVerificationToken": self.token
            })
        elif rtype == u'GET':
            response = requests.get(url, parameters, headers={
                "__RequestVerificationToken": self.token
            })
        return response

    def hw_req(self, api, payload=None, headers=None):
        log = self._log
        url = self.base_url+api
        log.debug('##############################################')
        log.debug('Server request: {0}'.format(pformat(url)))
        log.debug('##############################################')
        if payload:
            req = requests.post(url, data=payload, headers=headers)
        else:
            req = requests.post(url, headers=headers)
        if (req.status_code != 200):
            log.warning(url)
            log.warning(req)
            return False
        try:
            response = req.text
        except ValueError:
            return False
        log.debug('##############################################')
        log.debug('Server request: {0}'.format(pformat(response)))
        log.debug('##############################################')
        return req.text

    def _api_request(self, url, rtype=u'GET', parameters=None):
        log = self._log
        full_url = self.base_url + url
        resp_dict = {}
        log.debug('##############################################')
        log.debug('Server request: {0}'.format(pformat(url)))
        log.debug('##############################################')
        if parameters is not None:
            parameters_bytes = parameters.encode('UTF-8')
        else:
            parameters_bytes = None
        if (self.deviceName == u'E3372') or (self.token != u''):
            # il faut cookie et token
            # essai avec cookie courant
            response = self._api_request_token(full_url,
                                               rtype,
                                               parameters_bytes)
            try:
                resp_dict = self._parse_api_response(response)
            except TokenError:
                # demande nouveau cookie
                self._get_token_ext()
                response = self._api_request_token(full_url,
                                                   rtype,
                                                   parameters_bytes)
                resp_dict = self._parse_api_response(response)
        else:
            response = self._api_request_base(full_url,
                                              rtype,
                                              parameters_bytes)
            try:
                resp_dict = self._parse_api_response(response)
            except TokenError:
                # demande nouveau cookie
                if url != u'/webserver/token':
                    self._get_token()
                response = self._api_request_base(full_url,
                                                  rtype,
                                                  parameters_bytes)
                resp_dict = self._parse_api_response(response)

        log.debug('##############################################')
        log.debug('Server response: \n{0}'.format(pformat(resp_dict)))
        log.debug('##############################################')

        return resp_dict

    def _api_get(self, url):
        return self._api_request(url, rtype=u'GET', parameters=None)

    def _api_post(self, url, parameters):
        return self._api_request(url, rtype=u'POST', parameters=parameters)

    @property
    def base_url(self):
        return self._base_url

    @property
    def deviceName(self):
        if u'DeviceName' in self._infos.keys():
            return self._infos[u'DeviceName']
        else:
            return u''

    @property
    def macAddress1(self):
        if u'MacAddress1' in self._infos.keys():
            return self._infos[u'MacAddress1']
        else:
            return u''

    @property
    def imei(self):
        if u'Imei' in self._infos.keys():
            return self._infos[u'Imei']
        else:
            return u''

    @property
    def imsi(self):
        if u'Imsi' in self._infos.keys():
            return self._infos[u'Imsi']
        else:
            return u''

    @property
    def iccid(self):
        if u'Iccid' in self._infos.keys():
            return self._infos[u'Iccid']
        else:
            return u''

    @property
    def msisdn(self):
        if u'Msisdn' in self._infos.keys():
            return self._infos[u'Msisdn']
        else:
            return u''

    @property
    def hardwareVersion(self):
        if u'HardwareVersion' in self._infos.keys():
            return self._infos[u'HardwareVersion']
        else:
            return u''

    @property
    def softwareVersion(self):
        if u'SoftwareVersion' in self._infos.keys():
            return self._infos[u'SoftwareVersion']
        else:
            return u''

    @property
    def webUIVersion(self):
        if u'WebUIVersion' in self._infos.keys():
            return self._infos[u'WebUIVersion']
        else:
            return u''

    @property
    def macAddress2(self):
        if u'MacAddress2' in self._infos.keys():
            return self._infos[u'MacAddress2']
        else:
            return u''

    @property
    def productFamily(self):
        if u'ProductFamily' in self._infos.keys():
            return self._infos[u'ProductFamily']
        else:
            return u''

    @property
    def classify(self):
        if u'Classify' in self._infos.keys():
            return self._infos[u'Classify']
        else:
            return u''

    @property
    def supportmode(self):
        if u'supportmode' in self._infos.keys():
            return self._infos[u'supportmode']
        else:
            return u''

    @property
    def workmode(self):
        if u'workmode' in self._infos.keys():
            return self._infos[u'workmode']
        else:
            return u''

    @property
    def serialNumber(self):
        if u'SerialNumber' in self._infos.keys():
            return self._infos[u'SerialNumber']
        else:
            return u''

    @property
    def log(self):
        return self._log

    def _parse_api_response(self, response):
        if response.status_code == 200:
            payload = response.content
            parsed = xmltodict.parse(payload)

            # HAHA! HTTP response codes are for the weak!
            if 'response' in parsed:
                return parsed['response']
            else:
                code = parsed['error']['code']
                if str(code) == "125001":
                    raise TokenError()
                elif str(code) in ("125001", "125002"):
                    raise TokenError()
                if code in self._error_codes:
                    raise Exception(self._error_codes[str(code)])
                else:
                    raise Exception("Unknown error occurred")
        return {}


def main():

    def print_status(gsm):
        status = gsm.status
        print(u'\nStatus:')
        for k, v in status.items():
            print('  {}: {}'.format(k.ljust(10), v))

    def print_message_count(gsm, mtype=1):
        message_count = gsm.message_count
        print('\nmessage_count:')
        for k, v in message_count.items():
            if int(v) > 0:
                print('  {}: {}'.format(k.ljust(10), v))

        if (message_count['count'] > 0) and (mtype == 1):
            in_messages = gsm.in_messages
            print(u'\nin_messages:')
            for message in in_messages:
                print(message)
            return

        if (message_count['outbox'] > 0) and (mtype == 2):
            out_messages = gsm.out_messages
            print(u'\nout_messages:')
            for message in out_messages:
                print(message)

    #
    # parse arguments
    #
    loglevel = logging.INFO
    parser = argparse.ArgumentParser(description='Test module huawei_exxx.')
    parser.add_argument(u'--debug', u'-d', help='Logging debug', action="store_true")
    parser.add_argument(u'--warning', u'-w', help='Logging warning', action="store_true")
    parser.add_argument(u'--critical', u'-c', help='Logging critical', action="store_true")
    parser.add_argument(u'--list-out', u'-o', help='Out messages list', action="store_true")
    parser.add_argument(u'--list-in', u'-i', help='In messages list', action="store_true")
    parser.add_argument(u'--number', u'-n', help='Phone numbers comma separated')
    parser.add_argument(u'--text', u'-t', help='sms text')
    args = parser.parse_args()

    if args.debug:
        loglevel = logging.DEBUG
    if args.warning:
        loglevel = logging.WARNING
    if args.critical:
        loglevel = logging.CRITICAL
    import modem as modem
    gsm = modem.load(logLevel=loglevel)[0]
    print(gsm)
    print_status(gsm)
    if args.list_out:
        print_message_count(gsm, mtype=2)
    elif args.list_in:
        print_message_count(gsm)
    if args.number and args.text:
        print(args.number, args.text)
        gsm.send_sms(args.number, args.text)
        print_message_count(gsm, mtype=2)
        print_status(gsm)


if __name__ == '__main__':
    main()
