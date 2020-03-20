class SMSMessage:
    """A SMS message received by a modem"""
    message_id = ""
    message = ""
    sender  = ""
    dest    = ""
    phone   = ""
    receive_time = None
    send_time    = None
    rs_time      = None
    priority = 0

    def __repr__(self):
        if self.receive_time:
            return "<SMSMessage {} '{}' from '{}' time '{}'>".format(self.message_id, self.message, self.phone, self.rs_time)
        else:
            return "<SMSMessage {} '{}' to '{}' time '{}'>".format(self.message_id, self.message, self.phone, self.rs_time)