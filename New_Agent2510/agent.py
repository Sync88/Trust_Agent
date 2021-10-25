from socket import create_connection
from ssl import SSLContext, PROTOCOL_TLS_CLIENT


from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from tpm.tpm_main import tpm
from tpm.tpm_abstract import TPM_Utilities
import registrar_client

import http.server
import secure_mount
import config
import keylime_logging
import os
import base64
import threading
import crypto
import zipfile
import io
import shutil
import subprocess
import json
import time
from timeit import default_timer as timer

# Configure logger
logger = keylime_logging.init_logging('cloudagent')

uvLock = threading.Lock()

# Instaniate tpm
tpm_instance = tpm(need_hw_tpm=True)


class Handler(BaseHTTPRequestHandler):
    parsed_path = ''

    def do_HEAD(self):
        """Not supported"""
        config.echo_json_response(self, 405, "HEAD not supported")

    def do_GET(self):
        """This method services the GET request typically from either the Tenant or the Cloud Verifier.

        Only tenant and cloudverifier uri's are supported. Both requests require a nonce parameter.
        The Cloud verifier requires an additional mask paramter.  If the uri or parameters are incorrect, a 400 response is returned.
        """

        logger.info('GET invoked from %s with uri: %s', self.client_address, self.path)
        rest_params = config.get_restful_params(self.path)
        if rest_params is None:
            config.echo_json_response(
                self, 405, "Not Implemented: Use /keys/ or /quotes/ interfaces")
            return

        if "keys" in rest_params and rest_params['keys'] == 'verify':
            if self.server.K is None:
                logger.info('GET key challenge returning 400 response. bootstrap key not available')
                config.echo_json_response(
                    self, 400, "Bootstrap key not yet available.")
                return
            challenge = rest_params['challenge']
            response = {}
            response['hmac'] = crypto.do_hmac(self.server.K, challenge)
            config.echo_json_response(self, 200, "Success", response)
            logger.info('GET key challenge returning 200 response.')

        # If agent pubkey requested
        elif "keys" in rest_params and rest_params["keys"] == "pubkey":
            response = {}
            response['pubkey'] = self.server.rsapublickey_exportable

            config.echo_json_response(self, 200, "Success", response)
            logger.info('GET pubkey returning 200 response.')
            return

        elif "quotes" in rest_params:
            nonce = rest_params['nonce']
            pcrmask = rest_params['mask'] if 'mask' in rest_params else None
            vpcrmask = rest_params['vmask'] if 'vmask' in rest_params else None

            # if the query is not messed up
            if nonce is None:
                logger.warning('GET quote returning 400 response. nonce not provided as an HTTP parameter in request')
                config.echo_json_response(
                    self, 400, "nonce not provided as an HTTP parameter in request")
                return

            # Sanitization assurance (for tpm.run() tasks below)
            if not (nonce.isalnum() and (pcrmask is None or pcrmask.isalnum()) and (vpcrmask is None or vpcrmask.isalnum())):
                logger.warning('GET quote returning 400 response. parameters should be strictly alphanumeric')
                config.echo_json_response(
                    self, 400, "parameters should be strictly alphanumeric")
                return

            # identity quotes are always shallow
            hash_alg = tpm_instance.defaults['hash']
            if not tpm_instance.is_vtpm() or rest_params["quotes"] == 'identity':
                start_creating_quote = timer()
                
                quote = tpm_instance.create_quote(
                    nonce, self.server.rsapublickey_exportable, pcrmask, hash_alg)
                imaMask = pcrmask
                end_creating_quote = timer()
                with open("quote_creation_times.txt", "a") as f:
                    f.write("%f\n" % (end_creating_quote - start_creating_quote))
                logger.info('Quote creation time: %f sec' % (end_creating_quote - start_creating_quote))

            # Allow for a partial quote response (without pubkey)
            enc_alg = tpm_instance.defaults['encrypt']
            sign_alg = tpm_instance.defaults['sign']

            if "partial" in rest_params and (rest_params["partial"] is None or int(rest_params["partial"], 0) == 1):
                response = {
                    'quote': quote,
                    'hash_alg': hash_alg,
                    'enc_alg': enc_alg,
                    'sign_alg': sign_alg,
                }
            else:
                response = {
                    'quote': quote,
                    'hash_alg': hash_alg,
                    'enc_alg': enc_alg,
                    'sign_alg': sign_alg,
                    'pubkey': self.server.rsapublickey_exportable,
                }

            # return a measurement list if available
            if TPM_Utilities.check_mask(imaMask, config.IMA_PCR):
                if not os.path.exists(config.IMA_ML):
                    logger.warning("IMA measurement list not available: %s", config.IMA_ML)
                else:
                    with open(config.IMA_ML, 'r') as f:
                        ml = f.read()
                    response['ima_measurement_list'] = ml

            # similar to how IMA log retrievals are triggered by IMA_PCR, we trigger boot logs with MEASUREDBOOT_PCRs
            # other possibilities would include adding additional data to rest_params to trigger boot log retrievals
            # generally speaking, retrieving the 15Kbytes of a boot log does not seem significant compared to the
            # potential Mbytes of an IMA measurement list.
            if TPM_Utilities.check_mask(imaMask, config.MEASUREDBOOT_PCRS[0]):
                if not os.path.exists(config.MEASUREDBOOT_ML):
                    logger.warning("TPM2 event log not available: %s", config.MEASUREDBOOT_ML)
                else:
                    with open(config.MEASUREDBOOT_ML, 'rb') as f:
                        el = base64.b64encode(f.read())
                    response['mb_measurement_list'] = el

            config.echo_json_response(self, 200, "Success", response)
            logger.info('GET %s quote returning 200 response.', rest_params["quotes"])
            return

        else:
            logger.warning('GET returning 400 response. uri not supported: %s', self.path)
            config.echo_json_response(self, 400, "uri not supported")
            return

    def do_POST(self):
        """This method services the POST request typically from either the Tenant or the Cloud Verifier.

        Only tenant and cloudverifier uri's are supported. Both requests require a nonce parameter.
        The Cloud verifier requires an additional mask parameter.  If the uri or parameters are incorrect, a 400 response is returned.
        """
        rest_params = config.get_restful_params(self.path)

        if rest_params is None:
            config.echo_json_response(
                self, 405, "Not Implemented: Use /keys/ interface")
            return

        content_length = int(self.headers.get('Content-Length', 0))
        if content_length <= 0:
            logger.warning('POST returning 400 response, expected content in message. url: %s', self.path)
            config.echo_json_response(self, 400, "expected content in message")
            return

        post_body = self.rfile.read(content_length)
        json_body = json.loads(post_body)

        b64_encrypted_key = json_body['encrypted_key']
        decrypted_key = crypto.rsa_decrypt(
            self.server.rsaprivatekey, base64.b64decode(b64_encrypted_key))

        have_derived_key = False

        if rest_params["keys"] == "ukey":
            self.server.add_U(decrypted_key)
            self.server.auth_tag = json_body['auth_tag']
            self.server.payload = json_body.get('payload', None)
            have_derived_key = self.server.attempt_decryption()
        elif rest_params["keys"] == "vkey":
            self.server.add_V(decrypted_key)
            have_derived_key = self.server.attempt_decryption()
        else:
            logger.warning('POST returning  response. uri not supported: %s', self.path)
            config.echo_json_response(self, 400, "uri not supported")
            return
        logger.info('POST of %s key returning 200', ('V', 'U')[rest_params["keys"] == "ukey"])
        config.echo_json_response(self, 200, "Success")

        # no key yet, then we're done
        if not have_derived_key:
            return

        # woo hoo we have a key
        # ok lets write out the key now
        secdir = secure_mount.mount()  # confirm that storage is still securely mounted

        # clean out the secure dir of any previous info before we extract files
        if os.path.isdir("%s/unzipped" % secdir):
            shutil.rmtree("%s/unzipped" % secdir)

        # write out key file
        f = open(secdir + "/" + self.server.enc_keyname, 'w')
        f.write(base64.b64encode(self.server.K).decode())
        f.close()

        # stow the U value for later
        tpm_instance.write_key_nvram(self.server.final_U)

        # optionally extend a hash of they key and payload into specified PCR
        tomeasure = self.server.K

        # if we have a good key, now attempt to write out the encrypted payload
        dec_path = "%s/%s" % (secdir,
                              config.get('cloud_agent', "dec_payload_file"))
        enc_path = "%s/encrypted_payload" % config.WORK_DIR

        dec_payload = None
        enc_payload = None
        if self.server.payload is not None:
            dec_payload = crypto.decrypt(
                self.server.payload, bytes(self.server.K))

            enc_payload = self.server.payload
        elif os.path.exists(enc_path):
            # if no payload provided, try to decrypt one from a previous run stored in encrypted_payload
            with open(enc_path, 'rb') as f:
                enc_payload = f.read()
            try:
                dec_payload = crypto.decrypt(enc_payload, self.server.K)
                logger.info("Decrypted previous payload in %s to %s", enc_path, dec_path)
            except Exception as e:
                logger.warning("Unable to decrypt previous payload %s with derived key: %s", enc_path, e)
                os.remove(enc_path)
                enc_payload = None

        # also write out encrypted payload to be decrytped next time
        if enc_payload is not None:
            with open(enc_path, 'wb') as f:
                f.write(self.server.payload.encode('utf-8'))

        # deal with payload
        payload_thread = None
        if dec_payload is not None:
            tomeasure = tomeasure + dec_payload
            # see if payload is a zip
            zfio = io.BytesIO(dec_payload)
            if config.getboolean('cloud_agent', 'extract_payload_zip') and zipfile.is_zipfile(zfio):
                logger.info("Decrypting and unzipping payload to %s/unzipped", secdir)
                with zipfile.ZipFile(zfio, 'r')as f:
                    f.extractall('%s/unzipped' % secdir)

                # run an included script if one has been provided
                initscript = config.get('cloud_agent', 'payload_script')
                if initscript != "":
                    def initthread():
                        env = os.environ.copy()
                        env['AGENT_UUID'] = self.server.agent_uuid
                        proc = subprocess.Popen(["/bin/bash", initscript], env=env, shell=False, cwd='%s/unzipped' % secdir,
                                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                        while True:
                            line = proc.stdout.readline()
                            if line == '' and proc.poll() is not None:
                                break
                            if line:
                                logger.debug("init-output: %s", line.strip())
                        # should be a no-op as poll already told us it's done
                        proc.wait()

                    if not os.path.exists("%s/unzipped/%s" % (secdir, initscript)):
                        logger.info("No payload script %s found in %s/unzipped", initscript, secdir)
                    else:
                        logger.info("Executing payload script: %s/unzipped/%s", secdir, initscript)
                        payload_thread = threading.Thread(target=initthread)
            else:
                logger.info("Decrypting payload to %s", dec_path)
                with open(dec_path, 'wb') as f:
                    f.write(dec_payload)
            zfio.close()

        # now extend a measurement of the payload and key if there was one
        pcr = config.getint('cloud_agent', 'measure_payload_pcr')
        if 0 < pcr < 24:
            logger.info("extending measurement of payload into PCR %s", pcr)
            measured = tpm_instance.hashdigest(tomeasure)
            tpm_instance.extendPCR(pcr, measured)

        if payload_thread is not None:
            payload_thread.start()

        return

    # pylint: disable=W0622
    def log_message(self, format, *args):
        return

# consider using PooledProcessMixIn
# https://github.com/muayyad-alsadi/python-PooledProcessMixIn


class CloudAgentHTTPServer(ThreadingMixIn, HTTPServer):
    """Http Server which will handle each request in a separate thread."""

    # Do not modify directly unless you acquire uvLock. Set chosen for uniqueness of contained values
    u_set = set([])
    v_set = set([])

    rsaprivatekey = None
    rsapublickey = None
    rsapublickey_exportable = None
    done = threading.Event()
    auth_tag = None
    payload = None
    enc_keyname = None
    K = None
    final_U = None
    agent_uuid = None

    def __init__(self, server_address, RequestHandlerClass, agent_uuid):
        """Constructor overridden to provide ability to pass configuration arguments to the server"""
        secdir = secure_mount.mount()
        keyname = "%s/%s" % (secdir, config.get('cloud_agent', 'rsa_keyname'))
        # read or generate the key depending on configuration
        if os.path.isfile(keyname):
            # read in private key
            logger.debug("Using existing key in %s", keyname)
            f = open(keyname, "rb")
            rsa_key = crypto.rsa_import_privkey(f.read())
        else:
            logger.debug("key not found, generating a new one")
            rsa_key = crypto.rsa_generate(2048)
            with open(keyname, "wb") as f:
                f.write(crypto.rsa_export_privkey(rsa_key))

        self.rsaprivatekey = rsa_key
        self.rsapublickey_exportable = crypto.rsa_export_pubkey(
            self.rsaprivatekey)

        # attempt to get a U value from the TPM NVRAM
        nvram_u = tpm_instance.read_key_nvram()
        if nvram_u is not None:
            logger.info("Existing U loaded from TPM NVRAM")
            self.add_U(nvram_u)
        http.server.HTTPServer.__init__(
            self, server_address, RequestHandlerClass)
        self.enc_keyname = config.get('cloud_agent', 'enc_keyname')
        self.agent_uuid = agent_uuid

    def add_U(self, u):
        """Threadsafe method for adding a U value received from the Tenant

        Do not modify u_set of v_set directly.
        """
        with uvLock:
            # be very careful printing K, U, or V as they leak in logs stored on unprotected disks
            if config.INSECURE_DEBUG:
                logger.debug("Adding U len %d data:%s", len(u), base64.b64encode(u))
            self.u_set.add(u)

    def add_V(self, v):
        """Threadsafe method for adding a V value received from the Cloud Verifier
        Do not modify u_set of v_set directly.
        """
        with uvLock:
            # be very careful printing K, U, or V as they leak in logs stored on unprotected disks
            if config.INSECURE_DEBUG:
                logger.debug("Adding V: %s", base64.b64encode(v))
            self.v_set.add(v)

    def attempt_decryption(self):
        """On reception of a U or V value, this method is called to attempt the decryption of the Cloud Init script

        At least one U and V value must be received in order to attempt encryption. Multiple U and V values are stored
        to prevent an attacker from sending U/V values to deny service.
        """
        with uvLock:
            both_u_and_v_present = False
            return_value = False
            for u in self.u_set:
                for v in self.v_set:
                    both_u_and_v_present = True
                    return_value = self.decrypt_check(u, v)
                    if return_value:
                        # reset u and v sets
                        self.u_set = set([])
                        self.v_set = set([])
                        return return_value
            # TODO check on whether this happens or not.  NVRAM causes trouble
            if both_u_and_v_present:
                pass
                # logger.critical("Possible attack from: " + str(handler.client_address) + ".  Both U (potentially stale from TPM NVRAM) and V present but unsuccessful in attempt to decrypt check value.")
            return return_value

    def decrypt_check(self, decrypted_U, decrypted_V):
        """Decrypt the Cloud init script with the passed U and V values.

        This method will access the received auth tag, and may fail if decoy U and V values were received.
        Do not call directly unless you acquire uvLock. Returns None if decryption unsuccessful, else returns the
        decrypted agent UUID.
        """

        if self.auth_tag is None:
            return None

        if len(decrypted_U) != len(decrypted_V):
            logger.warning("Invalid U len %d or V len %d. skipping...", len(decrypted_U), len(decrypted_V))
            return None

        candidate_key = crypto.strbitxor(decrypted_U, decrypted_V)

        # be very careful printing K, U, or V as they leak in logs stored on unprotected disks
        if config.INSECURE_DEBUG:
            logger.debug("U: %s", base64.b64encode(decrypted_U))
            logger.debug("V: %s", base64.b64encode(decrypted_V))
            logger.debug("K: %s", base64.b64encode(candidate_key))

        logger.debug("auth_tag: %s", self.auth_tag)
        ex_mac = crypto.do_hmac(candidate_key, self.agent_uuid)

        if ex_mac == self.auth_tag:
            logger.info("Successfully derived K for UUID %s", self.agent_uuid)
            self.final_U = decrypted_U
            self.K = candidate_key
            return True

        logger.error("Failed to derive K for UUID %s", self.agent_uuid)

        return False

        

def main():

    instance_tpm = tpm()

    # initialize the tmpfs partition to store keys if it isn't already available

    # get params for initialization
    agent_uuid = config.get('cloud_agent', 'agent_uuid')
    registrar_ip = config.get('cloud_agent', 'registrar_ip')
    registrar_port = config.get('cloud_agent', 'registrar_port')

    # initialize the tmpfs partition to store keys if it isn't already available
    secdir = secure_mount.mount()  
    
    # change dir to working dir
    config.ch_dir(config.WORK_DIR, logger)


    # initialize tpm
    (ekcert, ek_tpm, aik_tpm) = instance_tpm.tpm_init(self_activate=False, config_pw="keylime")
    
    # SILVIOOOOOOOO ho commentato  instance_tpm.init_system_rand()

    # register it and get back a blob
    keyblob = registrar_client.doRegisterAgent(
        registrar_ip, registrar_port, agent_uuid, ek_tpm, ekcert, aik_tpm)


    if keyblob is None:
        instance_tpm.flush_keys()
        raise Exception("Registration failed")
        
        
    # get the ephemeral registrar key
    key = instance_tpm.activate_identity(keyblob)

    if key is None:
        instance_tpm.flush_keys()
        raise Exception("Activation failed")

    # tell the registrar server we know the key
    retval = False
    retval = registrar_client.doActivateAgent(
        registrar_ip, registrar_port, agent_uuid, key)

    if not retval:
        instance_tpm.flush_keys()
        raise Exception("Registration failed on activate")

    serveraddr = (config.get('cloud_agent', 'cloudagent_ip'),
                  config.getint('cloud_agent', 'cloudagent_port'))
    server = CloudAgentHTTPServer(serveraddr, Handler, agent_uuid)
    serverthread = threading.Thread(target=server.serve_forever)

    logger.info("Starting Cloud Agent on %s:%s use <Ctrl-C> to stop", serveraddr[0], serveraddr[1])
    serverthread.start()
    
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("TERM Signal received, shutting down...")
        instance_tpm.flush_keys()
        server.shutdown()


if __name__ == "__main__":
        main()
        
