import http.client
import os
from urllib.parse import urlparse
from urllib.parse import quote_plus
import webbrowser
import json
from urllib.parse import unquote
import base64
import xml.etree.ElementTree as ET
from signxml import XMLVerifier
import OpenSSL
from lxml import etree
import xmlsec


class Cohesion:

    def __init__(self):
        self._config = self._load_config()

    @staticmethod
    def _load_config(file_path='config.json'):
        with open(file_path, 'r') as f:
            config = json.load(f)
            config['sso.check.url.domain'] = urlparse(config['sso.check.url']).netloc
            config['sso.check.url.path'] = urlparse(config['sso.check.url']).path
            return config

    def _debug(self, txt):
        if self._config and self._config['debug']:
            print(txt)

    @staticmethod
    def _auth_encode(payload: str):

        message_bytes = payload.encode('ascii')
        base64_bytes = base64.b64encode(message_bytes)
        base64_message = base64_bytes.decode('ascii')
        return quote_plus(base64_message)

    @staticmethod
    def _auth_decode(payload: str):

        data = unquote(payload)
        message_bytes = base64.b64decode(data)
        return message_bytes.decode('ascii')

    def _create_auth_request(self, config: json):
        auth = f"<dsAuth xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"http://tempuri.org/Auth.xsd\"><auth><user /><id_sa /><id_sito>{self._config['site.ID_SITO']}</id_sito><esito_auth_sa /><id_sessione_sa /><id_sessione_aspnet_sa /><url_validate>{self._config['site.URLLogin']}</url_validate><url_richiesta>{self._config['site.IndexURL']}</url_richiesta><esito_auth_sso /><id_sessione_sso /><id_sessione_aspnet_sso /><stilesheet>{self._config['sso.additionalData']}</stilesheet></auth></dsAuth>"
        self._debug(f"raw auth parameter: {auth}")
        return self._auth_encode(auth)

    def _generate_WAYF_url_req(self):
        auth = self._create_auth_request(self._config)
        return f"https://{self._config['sso.check.url.domain']}/{self._config['sso.check.url.path']}?auth={auth}"

    def _get_sessions_from_auth(self, auth: str):
        payload = self._auth_decode(auth)
        self._debug(payload)
        root = ET.fromstring(payload)
        session_sso = root.find('.//{http://tempuri.org/Auth.xsd}id_sessione_sso').text
        session_aspnet_sso = root.find('.//{http://tempuri.org/Auth.xsd}id_sessione_aspnet_sso').text

        self._debug(f"session_sso:{session_sso}")
        self._debug(f"session_aspnet_sso:{session_aspnet_sso}")

        return session_sso, session_aspnet_sso

    def _webchecksso(self, operation='GetCredential', session_sso='', session_aspnet_sso='', xml_file_dump=None):
        domain = urlparse(self._config['sso.webCheckSessionSSO']).netloc
        path = urlparse(self._config['sso.webCheckSessionSSO']).path

        self._debug(f"SSO WebCheckSession domain: {domain}, path:{path}")

        conn = http.client.HTTPSConnection(domain)
        payload = f"Operation={operation}&IdSessioneSSO={session_sso}&IdSessioneASPNET={session_aspnet_sso}"
        self._debug(f"SSO WebCheckSession call payload: {payload}")

        headers = {
            'Connection': 'keep-alive',
            'sec-ch-ua': '"Opera";v="77", "Chromium";v="91", ";Not A Brand";v="99"',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36 OPR/77.0.4054.172',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': '*/*',
        }
        conn.request("POST", path, payload, headers)
        res = conn.getresponse()
        data = res.read()
        data_str = data.decode("utf-8")

        self._debug(f"SSO WebCheckSession call response: {data.decode('utf-8')}")
        if xml_file_dump:
            with open(xml_file_dump, 'wb') as f:
                f.write(data)
                f.close()

        self._verify_signature(data_str)

        return data_str, res.status

    def login(self, send_to_browser=True):
        wayf_url = self._generate_WAYF_url_req()

        self._debug(f"login url: {wayf_url}")

        if send_to_browser:
            webbrowser.open(wayf_url)

        return wayf_url

    def get_credential(self, data, dump_to_xml='response_get_credential.xml'):

        sso, aspnet_sso = self._get_sessions_from_auth(data)
        result = self._webchecksso(operation='GetCredential', session_sso=sso, session_aspnet_sso=aspnet_sso,
                                   xml_file_dump=dump_to_xml)
        return {
                   "sso_session_id": sso,
                   "aspnet_sso_session_id": aspnet_sso,
                   "user_data": result[0],
                   "request_status": result[1],
               },

    def logout(self, sso_session_id, aspnet_sso_session_id, dump_to_xml='response_logout.xml'):

        result = self._webchecksso(operation='LogoutSito', session_sso=sso_session_id,
                                   session_aspnet_sso=aspnet_sso_session_id,
                                   xml_file_dump=dump_to_xml)
        self._debug("logout response: {result[0]}")
        return result[1]

    def _verify_signature(self, data_str):
        return True
        # TODO: add proper signature verification

        # data_str = open('response_get_credential_signed.xml').read().encode('utf-8')
        #
        # template = etree.fromstring(data_str)
        # xmlsec.tree.add_ids(template, ["ID"])
        # signature_node = xmlsec.tree.find_node(template, xmlsec.constants.NodeSignature)
        # # Create a digital signature context (no key manager is needed).
        # ctx = xmlsec.SignatureContext()
        # key = xmlsec.Key.from_file('pubkey.pem', xmlsec.constants.KeyDataFormatPem)
        # # Set the key on the context.
        # ctx.key = key
        # ctx.verify(signature_node)
