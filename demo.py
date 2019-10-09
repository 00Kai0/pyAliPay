import OpenSSL
import hashlib


class AliPayDemo:
    def __init__(
        self,
        app_public_key_cert_string,  # 应用公钥证书
        alipay_public_key_cert_string,  # 支付宝公钥证书
        alipay_root_cert_string  # 支付宝根证书
    ):
        self._app_public_key_cert_string = app_public_key_cert_string
        self._alipay_public_key_cert_string = alipay_public_key_cert_string
        self._alipay_root_cert_string = alipay_root_cert_string
        self._alipay_public_key_string = self.load_alipay_public_key_string()

    def load_alipay_public_key_string(self):
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self._alipay_public_key_cert_string)
            return OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, cert.get_pubkey()).decode("utf-8")

    def get_cert_sn(self, cert):
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            certIssue = cert.get_issuer()
            string = certIssue.commonName + str(cert.get_serial_number())
            m = hashlib.md5()
            m.update(bytes(string, encoding="utf8"))
            return fileMD5(m.hexdigest())

    def read_pem_cert_chain(self, certContent):
        certs = list()
        for c in certContent.split('\n\n'):
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, c)
            certs.append(cert)
        return certs

    def get_root_cert_sn(self, rootCert):
        """
        """
        certs = self.read_pem_cert_chain(rootCert)
        rootCertSN = None
        for cert in certs:
            try:
                sigAlg = cert.get_signature_algorithm()
            except ValueError:
                continue
            if sigAlg == b'sha256WithRSAEncryption':
                certIssue = cert.get_issuer()
                string = certIssue.commonName + str(cert.get_serial_number())
                m = hashlib.md5()
                m.update(bytes(string, encoding="utf8"))
                certSN = fileMD5(m.hexdigest())
                if not rootCertSN:
                    rootCertSN = certSN
                else:
                    rootCertSN = rootCertSN + '_' + certSN
        return rootCertSN

    @property
    def app_cert_sn(self):
        return self.get_cert_sn(self._app_public_key_cert_string)

    @property
    def alipay_root_cert_sn(self):
        return self.get_root_cert_sn(self._alipay_root_cert_string)


def fileMD5(md5):
    return md5 if len(md5) == 32 else fileMD5('0' + md5)
