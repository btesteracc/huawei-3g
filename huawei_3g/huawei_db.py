import time
import sys
from datetime import datetime
import queue
import logging
import logging.handlers
from pprint import pformat
import argparse
import sqlite3
try:
    from huawei_3g.huawei_exxx import HuaweiModem
except ModuleNotFoundError:
    from huawei_exxx import HuaweiModem
try:
    from huawei_3g.datastructures import SMSMessage
except ModuleNotFoundError:
    from datastructures import SMSMessage
try:
    from huawei_3g import modem as modem
except ModuleNotFoundError:
    from modem import modem as modem


class HuaweiDb(HuaweiModem):

    qsearch_in_id = u'SELECT `ID`,`SenderNumber`,`RecipientID` FROM `inbox` WHERE `ID`=?;'
    qsearch_in = u'SELECT `ID`,`SenderNumber`,`RecipientID` FROM `inbox` WHERE `ReceivingDateTime`=? AND `SenderNumber`=?;'
    qinsert_in = u'INSERT INTO `inbox` (`ReceivingDateTime`,`Text`,`SenderNumber`,`RecipientID`,`UDH`) VALUES (?,?,?,?,?);'
    qdelete_in = u'DELETE FROM `inbox` WHERE `ID`=?;'

    qsearch_out_id = u'SELECT `ID`,`DestinationNumber`,`SenderID` FROM `outbox` WHERE `SenderID`=?;'
    qsearch_out = u'SELECT `ID`,`DestinationNumber`,`SenderID` FROM `outbox` WHERE `SendingDateTime`=? AND `DestinationNumber`=? AND `SenderID`=?;'
    qinsert_out = u'INSERT INTO `outbox` (`SendingDateTime`,`Text`,`DestinationNumber`,`SenderID`,`UDH`,`CreatorID`) VALUES (?,?,?,?,?,?);'
    qdelete_out = u'DELETE FROM `outbox` WHERE `ID`=?;'

    def __init__(self, interface, sysfs_path, log=None, logLevel=logging.INFO,
                 on_receive=None, on_send=None, on_event_parm=None,
                 db_file=None, update_db=False):

        if on_event_parm == 'self':
            self._on_event_parm = self

        HuaweiModem.__init__(self, interface=interface, sysfs_path=sysfs_path, log=log,
                             logLevel=logging.INFO, on_event_parm=self._on_event_parm,
                             on_receive=on_receive, on_send=on_send)

        self._db_file = db_file
        self._update_db = update_db
        self._cnx = None
        self._cursor = None

        if update_db:
            # self.update_db()
            log.debug(u'db updated')

    def get_cursor(self):
        try:
            cnx = sqlite3.connect(self._db_file)
        except sqlite3.Error as e:
            log.warning(u'erreur sqlite3: %s' % (e.args[0]))
            return(None, None)
        else:
            self._cursor = cnx.cursor()
            self._cnx = cnx
        return (self._cnx, self._cursor)

    def get_cursor_check(self):
        if self._cnx is None:
            self.get_cursor()
        elif self._cursor is None:
            self._cursor = cnx.cursor()
        return self._cnx

    def curs_update(self, query, params):
        result = False
        if self.get_cursor_check() is None:
            return
        try:
            self._cursor.execute(query, params)
            self._cnx.commit()
            result = True
        except sqlite3.Error as e:
            self.log.warning(u'erreur sqlite3: {}'.format(e.args[0]))
        return result

    def curs_read(self, query, params=None):
        result = None
        if self.get_cursor_check() is None:
            return
        try:
            if params is None:
                self._cursor.execute(query)
            else:
                self._cursor.execute(query, params)
        except sqlite3.Error as e:
            self.log.warning(u'erreur sqlite3: {}'.format(e.args[0]))
        return self._cursor

    def sms_in_db(self, sms):
        if sms.receive_time is not None:
            # qsearch_in = u'SELECT `ID`,`SenderNumber`,`RecipientID` FROM `inbox` WHERE `ReceivingDateTime`=? AND `SenderNumber`=?;'
            query = self.qsearch_in
            params = (sms.receive_time, sms.sender)
        else:
            # qsearch_out = u'SELECT `ID`,`DestinationNumber`,`SenderID` FROM `outbox` WHERE `SendingDateTime`=? AND `DestinationNumber`=? AND `SenderID`=?;'
            query = self.qsearch_out
            params = (sms.send_time, sms.phone, sms.message_id)
        curs = self.curs_read(query, params=params)
        if curs is None:
            return (None, None)
        rows = curs.fetchall()
        self.log.debug(rows)
        if len(rows) == 0:
            return (False, None)
        else:
            return (True, rows[0])

    def sms_store_in_db(self, sms):
        (in_db, row) = self.sms_in_db(sms)
        if in_db is None:
            return False
        if in_db:
            self.log.warning(u'sms already in db\n{}'.format(row))
            return True
        else:
            if sms.receive_time is not None:
                query = self.qinsert_in
                params = (sms.receive_time, sms.message, sms.sender, sms.message_id, '')
            else:
                query = self.qinsert_out
                params = (sms.send_time, sms.message, sms.phone, sms.message_id, 'Reserved', -1)
            result = self.curs_update(query, params)
            return result

    def sms_load_from_db(self, table, filter):
        if table == 'inbox':
            fields = ['ID', 'SenderNumber', 'Text', 'ReceivingDateTime', 'RecipientID']
        elif table == 'outbox':
            fields = ['ID', 'DestinationNumber', 'Text', 'SendingDateTime', 'SenderID']
        query = u'SELECT {} FROM {} WHERE {}';
        query = query.format(u','.join(fields), table, filter)
        curs = self.curs_read(query, params=None)
        if curs is None:
            return []
        rows = curs.fetchall()
        smss = []
        for row in rows:
            sms = SMSMessage()
            sms.message = row[2]
            sms.phone = row[1]
            sms.rs_time  = row[3]
            if table == 'inbox':
                sms.sender = row[1]
                sms.receive_time = row[3]
                sms.message_id = row[4]
            if table == 'outbox':
                sms.dest = row[1]
                sms.send_time = row[3]
                sms.message_id = row[4]
            smss.append(sms)
        return smss
        

    @property
    def db_file(self):
        return self._db_file

    @db_file.setter
    def db_file(self, value):
        self._db_file = value

    @property
    def update_db(self):
        return self._update_db

    @update_db.setter
    def update_db(self, value):
        self._update_db = value


def main():

    def find_gsm(logLevel=logging.INFO):
        gsms = []
        try:
            gsms = modem.load(logLevel=loglevel)
        except UnboundLocalError:
            pass
        trycount = 10
        while len(gsms) == 0:
            print(u'.', end='', flush=True)
            sys.stdout.flush()
            time.sleep(5)
            try:
                gsms = modem.load(logLevel=logLevel)
            except UnboundLocalError:
                pass
            trycount += -1
            if trycount == 0:
                return None
        print(u'')
        sys.stdout.flush()
        if trycount < 10:
            print(u'Waiting')
            for i in range(1, 10):
                time.sleep(1)
                print(u'.', end='', flush=True)
                sys.stdout.flush()
        return (gsms[0].interface, gsms[0].path)

    def on_receive(sms, param):
        print('<- {}'.format(sms))
        if param.db_file:
            print(u'result : {}\n{}'.format(param.sms_store_in_db(sms), sms))

    def on_send(sms, param):
        print('-> {}'.format(sms))
        if param.db_file:
            print(u'result : {}\n{}'.format(param.sms_store_in_db(sms), sms))

    #
    # parse arguments
    #
    loglevel = logging.INFO
    parser = argparse.ArgumentParser(description='Test module HuaweiDb.')
    parser.add_argument(u'--debug', u'-d', help='Logging debug', action="store_true")
    parser.add_argument(u'--warning', u'-w', help='Logging warning', action="store_true")
    parser.add_argument(u'--critical', u'-c', help='Logging critical', action="store_true")
    parser.add_argument(u'--update_db', u'-u', help='Update db', action="store_true")
    parser.add_argument(u'--dbfile', u'-f', help='Sqlite3 file')
    parser.add_argument(u'--idsms', u'-i', help='SMS ID')
    args = parser.parse_args()

    if args.debug:
        loglevel = logging.DEBUG
    if args.warning:
        loglevel = logging.WARNING
    if args.critical:
        loglevel = logging.CRITICAL
    import modem as modem

    modems = modem.find()
    if len(modems) == 0:
        print(u'No modem found')
        return
    modem = HuaweiDb(modems[0][u'interface'], modems[0][u'path'], log=None, logLevel=loglevel,
                     on_receive=on_receive, on_send=on_send, on_event_parm='self',
                     db_file=args.dbfile, update_db=False)
    print(modem)
    print(modem.in_messages)
    print(modem.out_messages)

    if args.dbfile:
        smss = modem.sms_load_from_db('inbox', "`RecipientID`='{}'".format(args.idsms))
        for sms in smss:
            print(u'message id (in):{}\n{}'.format(sms.message_id, sms))
        smss = modem.sms_load_from_db('outbox', "`SenderID`='{}'".format(args.idsms))
        for sms in smss:
            print(u'message id (out):{}\n{}'.format(sms.message_id, sms))


if __name__ == '__main__':
    main()
