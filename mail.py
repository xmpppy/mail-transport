#!/usr/bin/python
# coding: utf8
import os
try:
    version = ('git ' + open(
        os.path.join(os.path.dirname(__file__), '.git/refs/heads/master')
      ).read().strip())
except Exception:
    version = 'unknown'

import email
import signal
import smtplib
import sys
import time
import traceback
import xmpp
import logging
from xmpp.browser import *
from email.MIMEText import MIMEText
from email.Header import decode_header

import config
import xmlconfig


_log = logging.getLogger(__name__)


def get_html2text(config):
    try:
        import html2text as htmod
    except Exception, exc:
        _log.warning("html2text import failure: %r", exc)
        return lambda s: s  # dummy replacement

    ## TODO: use a newer version of html2text and the values from config.
    htmod.LINKS_EACH_PARAGRAPH = 1
    htmod.SKIP_INTERNAL_LINKS = 1
    # htmod.UNICODE_SNOB = 0  # default
    return htmod.html2text


def config_logging(config):
    ## TODO: use some actual config stuff
    logging.basicConfig(level=1)


class Transport:

    online = 1
    restart = 0
    offlinemsg = ''

    def __init__(self, jabber):
        self.jabber = jabber
        self.watchdir = os.path.expanduser(config.watchDir)
        # A list of two element lists, 1st is xmpp domain, 2nd is email domain
        self.mappings = [mapping.split('=') for mapping in config.domains]
        self.jto_fallback = config.fallbackToJid
        email.Charset.add_charset('utf-8', email.Charset.SHORTEST, None, None)

    def register_handlers(self):
        self.jabber.RegisterHandler('message', self.xmpp_message)
        self.jabber.RegisterHandler('presence', self.xmpp_presence)
        self.disco = Browser()
        self.disco.PlugIn(self.jabber)
        self.disco.setDiscoHandler(self.xmpp_base_disco, node='',
          jid=config.jid)

    # Disco Handlers
    def xmpp_base_disco(self, con, event, ev_type):
        fromjid = event.getFrom().__str__()
        to = event.getTo()
        node = event.getQuerynode()
        #Type is either 'info' or 'items'
        if to == config.jid:
            if node == None:
                if ev_type == 'info':
                    return dict(
                        ids=[dict(category='gateway', type='smtp',
                          name=config.discoName)],
                        features=[NS_VERSION, NS_COMMANDS])
                if ev_type == 'items':
                    return []
            else:
                self.jabber.send(Error(event, ERR_ITEM_NOT_FOUND))
                raise NodeProcessed
        else:
            self.jabber.send(Error(event, MALFORMED_JID))
            raise NodeProcessed

    #XMPP Handlers
    def xmpp_presence(self, con, event):
        # Add ACL support
        fromjid = event.getFrom()
        ev_type = event.getType()
        to = event.getTo()
        if ev_type == 'subscribe':
            self.jabber.send(Presence(to=fromjid, frm = to, typ = 'subscribe'))
        elif ev_type == 'subscribed':
            self.jabber.send(Presence(to=fromjid, frm = to, typ = 'subscribed'))
        elif ev_type == 'unsubscribe':
            self.jabber.send(Presence(to=fromjid, frm = to, typ = 'unsubscribe'))
        elif ev_type == 'unsubscribed':
            self.jabber.send(Presence(to=fromjid, frm = to, typ = 'unsubscribed'))
        elif ev_type == 'probe':
            self.jabber.send(Presence(to=fromjid, frm = to))
        elif ev_type == 'unavailable':
            self.jabber.send(Presence(to=fromjid, frm = to, typ = 'unavailable'))
        elif ev_type == 'error':
            return
        else:
            self.jabber.send(Presence(to=fromjid, frm = to))

    def xmpp_message(self, con, event):
        ev_type = event.getType()
        fromjid = event.getFrom()
        fromstripped = fromjid.getStripped()
        to = event.getTo()
        ## TODO? skip 'error' messages?
        ##  (example: recipient not found, `<message from='…'
        ##  to='…@pymailt.…' type='error' id='1'>…<error code='503'
        ##  type='cancel'>…<service-unavailable
        ##  xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>…`)
        if ev_type == 'error':
            ## Log properly? Send to fallbackjid (if not the error about it)?
            try:  # hax to plug it in
                raise Exception("Error XMPP message", event, str(event))
            except Exception as e:
                logError()
            return
        try:
            if event.getSubject.strip() == '':
                event.setSubject(None)
        except AttributeError:
            pass
        if event.getBody() == None:
            return

        if to.getNode() == '':
            self.jabber.send(Error(event, ERR_ITEM_NOT_FOUND))
            return
        mto = to.getNode().replace('%', '@')

        fromsplit = fromstripped.split('@', 1)
        mfrom = None
        for mapping in self.mappings:
            if mapping[0] == fromsplit[1]:
                mfrom = '%s@%s' % (fromsplit[0], mapping[1])

        if not mfrom:
            self.jabber.send(Error(event, ERR_REGISTRATION_REQUIRED))
            return

        subject = event.getSubject()
        body = event.getBody()
        ## TODO: Make it possible to ender subject as a part of message
        ##   (e.g.  `Sobject: ...` in the first line)
        ## TODO?: e-mail conversation tracking (reply-to)

        charset = 'utf-8'
        body = body.encode(charset, 'replace')

        msg = MIMEText(body, 'plain', charset)
        if subject:
            msg['Subject'] = subject
        msg['From'] = mfrom
        msg['To'] = mto

        try:
            if config.dumpProtocol:
                _log.info('SENDING: %r', msg.as_string())
            mailserver = smtplib.SMTP(config.smtpServer)
            if config.dumpProtocol:
                mailserver.set_debuglevel(1)
            mailserver.sendmail(mfrom, mto, msg.as_string())
            mailserver.quit()
        except:
            logError()
            self.jabber.send(Error(event, ERR_RECIPIENT_UNAVAILABLE))

    def mail_check(self):
        if time.time() < self.lastcheck + 5:
            return

        self.lastcheck = time.time()

        mails = os.listdir(self.watchdir)

        for mail in mails:
            fullname = '%s%s' % (self.watchdir, mail)
            fp = open(fullname)
            msg = email.message_from_file(fp)
            fp.close()
            os.remove(fullname)

            if config.dumpProtocol:
                _log.info('RECEIVING: %r', msg.as_string())

            mfrom = email.Utils.parseaddr(msg['From'])[1]
            ## XXXX: re-check this
            mto_base = msg['Envelope-To'] or msg['To']
            mto = email.Utils.parseaddr(mto_base)[1]

            ## XXXX/TODO: use `Message-id` or similar for resource (and
            ##   parse it in incoming messages)? Might have to also send
            ##   status updates for those.
            jfrom = '%s@%s' % (mfrom.replace('@', '%'), config.jid)

            tosplit = mto.split('@', 1)
            jto = None
            for mapping in self.mappings:
                #break  ## XXXXXX: hax: send everything to one place.
                if mapping[1] == tosplit[1]:
                    jto = '%s@%s' % (tosplit [0], mapping[0])

            if not jto:
                ## XXX: actual problem is in, e.g., maillists mail, which is
                ##   sent to the maillist and not to the recipient. This is
                ##   more like a temporary haxfix for that.
                jto = self.jto_fallback
                if not jto:
                    continue

            (subject, charset) = decode_header(msg['Subject'])[0]
            if charset:
                subject = unicode(subject, charset, 'replace')

            log = _log.debug

            log("processing email message %s", repr(msg)[:60])
            msg_plain = msg_html = None
            submessages = msg.get_payload()
            for submessage in submessages:
                # msg = msg.get_payload(0)
                if not submessage:
                    continue
                ctype = submessage.get_content_type()
                # NOTE: 'startswith' might be nore correct, but this should
                # be okay too
                if 'text/html' in ctype:
                    log("msg: found text/html")
                    msg_html = submessage
                elif 'text/plain' in ctype:
                    log("msg: found text/plain")
                    msg_plain = submessage
                else:
                    log("msg: unprocessed ctype %r" % (ctype,))

            if config.preferredFormat == 'plaintext':
                log("msg: preferring plaintext")
                msg = msg_plain or msg_html or msg  # first whatever
            else:  # html2text or html
                log("msg: preferring html")
                msg = msg_html or msg_plain or msg
                log("msg: resulting content_type is %r" % (msg.get_content_type(),))

            charset = msg.get_charsets('utf-8')[0]
            body = msg.get_payload(None, True)
            body = unicode(body, charset, 'replace')
            # check for `msg.get_content_subtype() == 'html'` instead?
            if 'text/html' in msg.get_content_type():
                if config.preferredFormat != 'html':
                    log("msg: doing html2text")
                    html2text = get_html2text(config)
                    body = html2text(body)
                # TODO: else compose an XMPP-HTML message? Will require a
                # complicated preprocessor like bs4 though

            # TODO?: optional extra headers (e.g. To if To != Envelope-To)
            # prepended to the body.
            m = Message(to=jto, frm=jfrom, subject=subject, body=body)
            self.jabber.send(m)

    def xmpp_connect(self):
        connected = self.jabber.connect((config.mainServer, config.port))
        if config.dumpProtocol:
            _log.info("connected: %r", connected)
        while not connected:
            time.sleep(5)
            connected = self.jabber.connect((config.mainServer, config.port))
            if config.dumpProtocol:
                _log.info("connected: %r", connected)
        self.register_handlers()
        if config.dumpProtocol:
            _log.info("trying auth")
        connected = self.jabber.auth(config.saslUsername, config.secret)
        if config.dumpProtocol:
            _log.info("auth return: %r", connected)
        return connected

    def xmpp_disconnect(self):
        time.sleep(5)
        if not self.jabber.reconnectAndReauth():
            time.sleep(5)
            self.xmpp_connect()


def loadConfig():
    configOptions = {}
    for configFile in config.configFiles:
        if os.path.isfile(configFile):
            xmlconfig.reloadConfig(configFile, configOptions)
            config.configFile = configFile
            return
    sys.stderr.write(("Configuration file not found. "
      "You need to create a config file and put it "
      " in one of these locations:\n ")
      + "\n ".join(config.configFiles))
    sys.exit(1)


def logError():
    err = '%s - %s\n' % (time.strftime('%a %d %b %Y %H:%M:%S'), version)
    if logfile != None:
        logfile.write(err)
        traceback.print_exc(file=logfile)
        logfile.flush()
    sys.stderr.write(err)
    traceback.print_exc()
    sys.exc_clear()


def sigHandler(signum, frame):
    transport.offlinemsg = 'Signal handler called with signal %s' % (signum,)
    if config.dumpProtocol:
        print 'Signal handler called with signal %s' % (signum,)
    transport.online = 0


if __name__ == '__main__':
    if 'PID' in os.environ:
        config.pid = os.environ['PID']
    loadConfig()
    if config.pid:
        pidfile = open(config.pid,'w')
        pidfile.write(`os.getpid()`)
        pidfile.close()

    config_logging(config)
    logfile = None
    if config.debugFile:
        logfile = open(config.debugFile, 'a')

    if config.saslUsername:
        sasl = 1
    else:
        config.saslUsername = config.jid
        sasl = 0

    if config.dumpProtocol:
        debug = ['always', 'nodebuilder']
    else:
        debug = []
    connection = xmpp.client.Component(config.jid, config.port, debug=debug,
      sasl=sasl, bind=config.useComponentBinding, route=config.useRouteWrap)
    transport = Transport(connection)
    if not transport.xmpp_connect():
        print "Could not connect to server, or password mismatch!"
        sys.exit(1)
    # Set the signal handlers
    signal.signal(signal.SIGINT, sigHandler)
    signal.signal(signal.SIGTERM, sigHandler)
    transport.lastcheck = time.time() + 10
    while transport.online:
        try:
            connection.Process(1)
            transport.mail_check()
        except KeyboardInterrupt:
            _pendingException = sys.exc_info()
            raise _pendingException[0], _pendingException[1], _pendingException[2]
        except IOError:
            transport.xmpp_disconnect()
        except:
            logError()
        if not connection.isConnected():
            transport.xmpp_disconnect()
    connection.disconnect()
    if config.pid:
        os.unlink(config.pid)
    if logfile:
        logfile.close()
    if transport.restart:
        args = [sys.executable] + sys.argv
        if os.name == 'nt':
            args = ["\"%s\"" % (a,) for a in args]
        if config.dumpProtocol:
            print sys.executable, args
        os.execv(sys.executable, args)
