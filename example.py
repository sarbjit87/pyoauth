from pyoauth import OAuth1 as Oauth

# Example for Twitter

CONSUMER_KEY = "your consumer key"
CONSUMER_SECRET = "your consumer secret key"

oauthInst = Oauth(consumerKey=CONSUMER_KEY,consumerSecret=CONSUMER_SECRET)    

# Request token
oauthInst.requestToken(url="https://api.twitter.com/oauth/request_token")
# Authorize user
oauthInst.authorizeUser(url="https://api.twitter.com/oauth/authorize")
# Request access token
oauthInst.accessToken(url="https://api.twitter.com/oauth/access_token")
# Access resource
oauthInst.accessResource("https://api.twitter.com/1.1/account/settings.json")
