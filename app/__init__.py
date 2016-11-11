from flask import Flask,render_template,flash
from flask import url_for, request, session, redirect
from rauth.service import OAuth2Service
import json
import httplib

app=Flask(__name__)
app.secret_key='dfgkjzbvjxnvlndnksvjnkxvbjxnvkbvjnkv'

facebook = OAuth2Service(name='facebook',
                         authorize_url='https://www.facebook.com/dialog/oauth',
                         access_token_url='https://graph.facebook.com/oauth/access_token',
                         client_id='1749530795331028',
                         client_secret='7199b7eede3307ac31c5904311ea3ae2',
                         base_url='https://graph.facebook.com/')
google = OAuth2Service(name='google',
                         authorize_url='https://accounts.google.com/o/oauth2/auth',
                         access_token_url='https://accounts.google.com/o/oauth2/token',
                         client_id='224959459599-na42re763nq6pejde7gakrdvtp1vvmnu.apps.googleusercontent.com',
                         client_secret='6-Apc2roCR23wlgoS-HaJ8bA',
                         base_url='https://googleapis.com/oauth2/v1/')

@app.route('/')
def home():
    return render_template("home.html",user_info=session.get('user_info'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('token', None)
    session.pop('user_info',None)
    session.pop('with',None)
    return redirect(url_for('home'))
    
@app.route('/facebook/login')
def fb_login():
    redirect_uri = url_for('fb_authorized', _external=True)
    params = {'redirect_uri': redirect_uri}
    return redirect(facebook.get_authorize_url(**params))

@app.route('/facebook/authorized')
def fb_authorized():
    # check to make sure the user authorized the request    
    if not 'code' in request.args:
        flash('You did not authorize the request')
        return redirect(url_for('home'))
    
    # make a request for the access token credentials using code
    redirect_uri = url_for('fb_authorized', _external=True)
    data = dict(code=request.args['code'], redirect_uri=redirect_uri)

    fb_session = facebook.get_auth_session(data=data)
    
    # the "me" response
    # me = fb_session.get('me').json()
    
    session['logged_in']=True
    session['with']='facebook'
    session['token']=fb_session.access_token
    
    c  = httplib.HTTPSConnection("graph.facebook.com")
    c.request("GET", "/me?access_token="+session.get('token')+"&fields=name,email,gender,first_name,last_name,link")
    response = c.getresponse()
    # print response.status, response.reason
    user_info = response.read()
    
    session['user_info']= json.loads(user_info)
    
    return redirect(url_for('home'))

@app.route('/google/login')
def google_login():
    redirect_uri = url_for('google_authorized', _external=True)
    params = {'redirect_uri': redirect_uri,
              'response_type': 'code',
              'scope': 'email'}
    return redirect(google.get_authorize_url(**params))

@app.route('/google/authorized')
def google_authorized():
    # check to make sure the user authorized the request
    if not 'code' in request.args:
        flash('You did not authorize the request')
        return redirect(url_for('home'))
    
    # make a request for the access token credentials using code
    redirect_uri = url_for('google_authorized', _external=True)
    data = dict(code=request.args['code'], redirect_uri=redirect_uri,grant_type='authorization_code')
        
    google_session = google.get_raw_access_token(data=data)
    google_session=google_session.json()
    
    session['logged_in']=True
    session['with']='google'
    session['token']=google_session['access_token']
    
    c = httplib.HTTPSConnection("www.googleapis.com")
    c.request("GET", "/plus/v1/people/me?access_token="+session.get('token'))
    response = c.getresponse()
    # print response.status, response.reason
    user_info = response.read()
    
    session['user_info']= json.loads(user_info)
    
    return redirect(url_for('home'))
    
if __name__ == "__main__":
    app.debug=True
    app.run()