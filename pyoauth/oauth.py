import urllib
import urllib2
from urlparse import urlparse, parse_qsl, parse_qs
import time 
import hmac
import hashlib
import random
import base64
import collections
import binascii
import random
import string
import webbrowser

class OAuth1(object):
    def __init__(self,
                 consumerKey=None,
                 consumerSecret=None,
                 httpMethod="POST",
                 requestTokenURL=None,
                 userAuthorizationURL=None,
                 accessTokenURL=None
                 ):
        self.consumerKey = consumerKey
        self.consumerSecret = consumerSecret
        self.httpMethod = httpMethod
        self.requestTokenURL = requestTokenURL
        self.userAuthorizarionURL = userAuthorizationURL
        self.accessTokenURL = accessTokenURL
        self._oauthVerifier = ""
        self.oauthTokenSecret = ""
        self._requestToken = ""
        self._requestTokenSecret = ""
        self._accessToken = ""
        self._accessTokenSecret = ""
        self.callBack = "http://127.0.0.1/oauth1_callback"

    def _url_encode(self,s):
        return urllib.quote(str(s),safe='')

    def _getNonce(self):
        s = string.ascii_letters + string.digits
        return ''.join(random.sample(s,20))

    def _getTimeStamp(self):
        return int(time.time())
    
    def _get_signature(self,signingKey,signingText,signingMethod):
        sig = hmac.new(signingKey,signingText,signingMethod)
        return base64.b64encode(sig.digest())
    
    def _getBaseString(self,url,params):
        params.sort()
        normalizedParams = urllib.urlencode(params)
        basestring = self.httpMethod + "&" + self._url_encode(url) + "&" + self._url_encode(normalizedParams)
        return basestring
    
    def _getAuthorizationHeader(self,params):
        params = dict(params)
        sortedParams = {}
        sortedParams = collections.OrderedDict(sorted(params.items()))
        authHeader = (
        '%s="%s"' % (k, self._url_encode(v)) for k, v in sortedParams.iteritems())
        retval = "OAuth " + ', '.join(authHeader)
        return retval
        
    def requestToken(self,url):
        parameters_request_token = [
            ('oauth_consumer_key', self.consumerKey),
            ('oauth_signature_method', 'HMAC-SHA1'),
            ('oauth_callback', self.callBack),
            ('oauth_timestamp', self._getTimeStamp()),
            ('oauth_nonce', self._getNonce()),
            ('oauth_version', '1.0')
            ]
        
        baseString = self._getBaseString(url,parameters_request_token)
        signingKey = self.consumerSecret + "&"  + ""
        signedString = self._get_signature(signingKey,baseString,hashlib.sha1)
        parameters_request_token.append(('oauth_signature',signedString))
        
        requrl = "?".join((url, urllib.urlencode(parameters_request_token)))
        resp = urllib2.urlopen(urllib2.Request(requrl,data=[]))
        assert resp.code == 200
        resp_content = dict(parse_qsl(resp.read()))
        self._requestToken, self._requestTokenSecret = resp_content['oauth_token'], resp_content['oauth_token_secret']

    def authorizeUser(self,url):
        assert self._requestToken != "", "No request token found"
        assert self._requestTokenSecret != "", "No request token secret found"
        authurl = url + "?oauth_token=" + self._requestToken
        webbrowser.open(authurl)
        print "Since this option is called from Command Line, please copy/paste the results from webbrowser"
        respWebBrowser = raw_input("Enter the response (web-address) from Web Browser")
        respData = dict(parse_qsl(urlparse(respWebBrowser).query))
        self._oauthVerifier = respData['oauth_verifier']

    def accessToken(self,url):
        assert self._oauthVerifier != "", "No oauth verifier found"
        
        parameters_access_token = [
            ('oauth_consumer_key', self.consumerKey),
            ('oauth_signature_method', 'HMAC-SHA1'),
            ('oauth_callback', self.callBack),
            ('oauth_timestamp', self._getTimeStamp()),
            ('oauth_nonce', self._getNonce()),
            ('oauth_version', '1.0'),
            ('oauth_token', self._requestToken),
            ('oauth_verifier', self._oauthVerifier)
            ]
        
        baseString = self._getBaseString(url,parameters_access_token)
        signingKey = self.consumerSecret + "&"  + self._requestTokenSecret
        signedString = self._get_signature(signingKey,baseString,hashlib.sha1)
        parameters_access_token.append(('oauth_signature',signedString))
        
        accessurl = "?".join((url, urllib.urlencode(parameters_access_token)))
        resp = urllib2.urlopen(urllib2.Request(accessurl,data=[]))
        assert resp.code == 200
        resp_content = dict(parse_qsl(resp.read()))
        self._accessToken, self._accessTokenSecret = resp_content['oauth_token'], resp_content['oauth_token_secret']

    def accessResource(self,url):
        assert self._accessToken != "", "No access token found"
        assert self._accessTokenSecret != "", "No access token secret found"
        
        parameters_access_resource = [
            ('oauth_consumer_key', self.consumerKey),
            ('oauth_signature_method', 'HMAC-SHA1'),
            ('oauth_timestamp', self._getTimeStamp()),
            ('oauth_nonce', self._getNonce()),
            ('oauth_version', '1.0'),
            ('oauth_token', self._accessToken),
            ]
        
        baseString = self._getBaseString(url,parameters_access_resource)
        signingKey = self.consumerSecret + "&"  + self._accessTokenSecret
        signedString = self._get_signature(signingKey,baseString,hashlib.sha1)
        parameters_access_resource.append(('oauth_signature',signedString))
        
        reqobj = urllib2.Request(url, data=[],headers={"Authorization":self._getAuthorizationHeader(parameters_access_resource)})
        try:
            resp = urllib2.urlopen(reqobj)
        except urllib2.HTTPError as e:
            error_message = e.read()
            print error_message     
        assert resp.code == 200
        print resp.read()
