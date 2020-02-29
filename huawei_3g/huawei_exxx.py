import requests
import xmltodict
import datetime
import netifaces
import queue
import logging
import logging.handlers
from pprint import pformat
from huawei_3g.datastructures import SMSMessage


class TokenError(Exception):
    pass


class HuaweiModem:
    """ This class abstracts the communication with a
    Huawei HiLink E303 modem"""
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
        """ Create instance of the HuaweiE303Modem class

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
        self.base_url = "http://{}/api".format(self.ip)
        self.token = ""
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
        self._log.info(u'{}'.format(self._infos))
        # self._get_token()

    def get_device_infos(self):
        status_raw = self._api_get("/device/information")
        return(status_raw)

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
            'unread': int(messages_raw['LocalUnread'])
        }

    def get_messages(self, delete=False):
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
                             "<BoxType>1</BoxType>"
                             "<SortType>0</SortType>"
                             "<Ascending>0</Ascending>"
                             "<UnreadPreferred>0</UnreadPreferred>"
                             "</request>")
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
            sms.sender = message['Phone']
            receive_time = message['Date']
            sms.receive_time = datetime.datetime.strptime(receive_time, '%Y-%m-%d %H:%M:%S')
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
        by :func:`~huawei_3g.HuaweiE303Modem.get_messages`
        """
        return self.delete_messages([message_id])

    def delete_messages(self, ids):
        """ Delete multiple SMS messages from the modem

        This does the same thing as :func:`~huawei_3g.HuaweiE303Modem.delete_message` but accepts a list of message
        indexes to delete them in a single API call.
        """
        xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><request>"
        for message_id in ids:
            xml += "<Index>{}</Index>".format(message_id)
        xml += "</request>"
        self._api_post("/sms/delete-sms", xml)

    def send_sms(self, number, message):
        """ Added 04th june 2017 by Bjoern"""
        mxml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><request><Index>-1</Index>"
        mxml += "<Phones><Phone>{}</Phone></Phones><Sca/>".format(number)
        mxml += "<Content>{}</Content>".format(message)
        mxml += "<Length>{}</Length><Reserved>1</Reserved>".format(len(message))
        mxml += "<Date>{}</Date></request>".format(datetime.datetime.strftime(datetime.datetime.now(),
                                                                              '%Y-%m-%d %H:%M:%S'))
        self._api_post("/sms/send-sms", mxml)

    def connect(self):
        xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><request><Action>1</Action></request>"
        self._api_post("/dialup/dial", xml)

    def disconnect(self):
        xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><request><Action>0</Action></request>"
        self._api_post("/dialup/dial", xml)

    def __repr__(self):
        return "<HuaweiE303Modem {} ({})>".format(self.interface, self.path)

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
    def deviceName(self):
        if u'DeviceName' in self._infos.keys():
            return self._infos[u'DeviceName']
        else:
            return u''

    @property
    def macaddress(self):
        return self._infos[u'macaddress1']

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
