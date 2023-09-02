from flask import Flask, request, render_template, session, redirect, url_for  
import boto3
import hmac
import hashlib
import base64

app = Flask(__name__)
#ADD A BETTER SECRET KEY LATER
app.secret_key = '1234'
COGNITO_REGION = 'ap-south-1'
COGNITO_USER_POOL_ID = 'ap-south-1_hGhZFdcTG'
COGNITO_APP_CLIENT_ID = '6ggsv44k21d86u3tdlgje0ct0m'
IDENTITY_POOL_ID = 'ap-south-1:7d72942f-f556-42e4-b72c-04e863561f18'
BUCKET_NAME = 'diamond-inclusion-demo-bucket'


cognito_user = boto3.client('cognito-idp', region_name=COGNITO_REGION)
cognito_identity = boto3.client('cognito-identity', region_name = COGNITO_REGION)

@app.route('/')
@app.route('/login', methods = ['GET', 'POST'])
def login():
    
    if request.method == 'POST':
        
        username = request.form['username']
        password = request.form['password']
        
        try:
            
            secret_hash = calculate_secret_hash(username)
            response = cognito_user.initiate_auth(
                ClientId=COGNITO_APP_CLIENT_ID,
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': username,
                    'PASSWORD': password,
                    'SECRET_HASH': secret_hash
                }
            )
            session['access_token'] = response['AuthenticationResult']['AccessToken']
            session['id_token'] = response['AuthenticationResult']['IdToken']
            
            response = cognito_identity.get_id(
            IdentityPoolId=IDENTITY_POOL_ID,
            Logins={
                'cognito-idp.ap-south-1.amazonaws.com/ap-south-1_hGhZFdcTG': session['id_token']
                }
            )

            identity_id = response['IdentityId']
            response = cognito_identity.get_credentials_for_identity(
            IdentityId = identity_id
            )

            credentials = response['Credentials']
            
            print(credentials)
            
            return redirect(url_for('protected'))
        
        except Exception as e:
            #FIX THIS WITH SOMETHING MORE APPROPRIATE BEFORE SEND IT IN 
            return str(e)
            
    else: 
        return render_template("login.html")
    
@app.route('/protected')
def protected():
    if 'access_token' in session:
        
        return "Protected Content"
    else:
        return redirect(url_for('login'))

def calculate_secret_hash(username):
    secret = 't8ti4aa3qftvtllbklovumfju0g623blhaamsie3rqtl60utgfs'
    message = username + COGNITO_APP_CLIENT_ID
    dig = hmac.new(secret.encode('utf-8'), msg=message.encode('utf-8'), digestmod=hashlib.sha256).digest()
    return base64.b64encode(dig).decode()

if __name__  == '__main__':
    
    app.run(debug = True, port = 5000)