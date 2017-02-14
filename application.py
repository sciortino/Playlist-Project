from flask import Flask, render_template, request, \
    redirect, jsonify, url_for, flash, g
app = Flask(__name__)

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from db_setup import Base, User, Playlist, Track
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
import base64
import urllib

from functools import wraps

# Connect to Database and create database session
engine = create_engine('sqlite:///playlistModel.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Begin Authentication

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Music Playlist Application"


# Login Decorator function
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in login_session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

# Create a state token to prevent request forgery.
# Store it in the session for later validation.


@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase +
                                  string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=' \
        'fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=' \
        '%s' % (app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook/com/v2.4/me"
    # Strip expire tag from access token
    token = result.split("&")[0]

    url = 'https://graph.facebook.com/v2.4/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly
    # logout, let's strip out the information before the equals sign in our
    # token
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Get user picture
    url = 'https://graph.facebook.com/v2.4/me/picture?%s' \
        '&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;" \
        "-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (
        facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1].decode("utf8"))
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print ("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['provider'] = 'google'
    login_session['credentials'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # see if user exists, if it doesn't then make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;" \
        "-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print ("done!")
    return output

# DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('credentials')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print (login_session['access_token'])
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % \
        login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print ('result is ')
    print (result)
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            del login_session['gplus_id']
            del login_session['credentials']
        if login_session['provider'] == 'facebook':
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showPlaylists'))
    else:
        flash("You were not logged in to begin with!")
        return redirect(url_for('showPlaylists'))

# JSON APIs to view Playlist and Track Information


@app.route('/playlist/<int:playlist_id>/track/JSON')
@login_required
def playlistTrackJSON(playlist_id):
    tracks = session.query(Track).filter_by(playlist_id=playlist_id).all()
    return jsonify(Tracks=[t.serialize for t in tracks])


@app.route('/playlist/<int:playlist_id>/track/<int:track_id>/JSON')
@login_required
def trackJSON(playlist_id, track_id):
    track = session.query(Track).filter_by(id=track_id).one()
    playlist = session.query(Playlist).filter_by(id=playlist_id).one()
    return jsonify(Tracks=track.serialize, Playlists=playlist.serialize)


@app.route('/playlist/JSON')
@login_required
def playlistJSON():
    playlists = session.query(Playlist).all()
    return jsonify(playlists=[p.serialize for p in playlists])


# Show all Playlists

@app.route('/')
@app.route("/playlist/")
def showPlaylists():
    playlists = session.query(Playlist).order_by(asc(Playlist.id))
    return render_template("playlists.html", playlists=playlists)

# Create new Playlist


@app.route('/playlist/new/', methods=['GET', 'POST'])
@login_required
def newPlaylist():
    if request.method == 'POST':
        newPlaylist = Playlist(
            name=request.form['name'], user_id=login_session['user_id'])
        session.add(newPlaylist)
        flash('New Playlist %s Successfully Created' % newPlaylist.name)
        session.commit()
        return redirect(url_for('showPlaylists'))
    else:
        return render_template('new_playlist.html')

# Edit a playlist


@app.route('/playlist/<int:playlist_id>/edit/', methods=['GET', 'POST'])
@login_required
def editPlaylist(playlist_id):
    editedPlaylist = session.query(Playlist).filter_by(id=playlist_id).one()
    if editedPlaylist.user_id != login_session['user_id']:
        flash('You are not authorized to edit this playlist.')
        return redirect('/playlist')
    if request.method == 'POST':
        if request.form['name']:
            editedPlaylist.name = request.form['name']
            flash('Playlist Successfully Edited %s' % editedPlaylist.name)
            return redirect(url_for('showPlaylists'))
    else:
        return render_template('edit_playlist.html', playlist=editedPlaylist)


# Delete a playlist
@app.route('/playlist/<int:playlist_id>/delete/', methods=['GET', 'POST'])
@login_required
def deletePlaylist(playlist_id):
    playlistToDelete = session.query(Playlist).filter_by(id=playlist_id).one()
    if playlistToDelete.user_id != login_session['user_id']:
        flash('You are not authorized to delete this playlist.')
        return redirect('/playlist')
    if request.method == 'POST':
        session.delete(playlistToDelete)
        flash('%s Successfully Deleted' % playlistToDelete.name)
        session.commit()
        return redirect(url_for('showPlaylists', playlist_id=playlist_id))
    else:
        return render_template('delete_playlist.html',
                               playlist=playlistToDelete)


# Show all tracks in a playlist
@app.route("/playlist/<int:playlist_id>/")
@app.route("/playlist/<int:playlist_id>/track")
def showTracks(playlist_id):
    playlist = session.query(Playlist).filter_by(id=playlist_id).one()
    creator = getUserInfo(playlist.user_id)
    tracks = session.query(Track).filter_by(playlist_id=playlist_id).all()
    return render_template("tracks.html", tracks=tracks,
                           playlist=playlist, creator=creator)

# Add a new track to a playlist


@app.route('/playlist/<int:playlist_id>/track/new/', methods=['GET', 'POST'])
@login_required
def newTrack(playlist_id):
    playlist = session.query(Playlist).filter_by(id=playlist_id).one()
    if request.method == 'POST':
        newTrack = Track(name=request.form['name'],
                         artist=request.form['artist'],
                         album=request.form['album'],
                         playlist_id=playlist_id,
                         user_id=login_session['user_id'])
        session.add(newTrack)
        session.commit()
        flash('New Track "%s" added to your playlist: "%s"!' %
              (newTrack.name, playlist.name))
        return redirect(url_for('showTracks', playlist_id=playlist_id))
    else:
        return render_template('new_track.html', playlist_id=playlist_id)

# Edit a track


@app.route('/playlist/<int:playlist_id>/track/<int:track_id>/edit',
           methods=['GET', 'POST'])
@login_required
def editTrack(playlist_id, track_id):
    editedTrack = session.query(Track).filter_by(id=track_id).one()
    playlist = session.query(Playlist).filter_by(id=playlist_id).one()
    if editedTrack.user_id != login_session['user_id']:
        return "<script>function myFunction() " \
               "{alert('You are not authorized to edit this track. " \
               "Please create your own playlist and track to edit.');" \
               "window.location = '/playlist' }" \
               "</script><body onload='myFunction()''>"
    if request.method == 'POST':
        if request.form['name']:
            editedTrack.name = request.form['name']
        if request.form['artist']:
            editedTrack.artist = request.form['artist']
        if request.form['album']:
            editedTrack.album = request.form['album']
        session.add(editedTrack)
        session.commit()
        flash('Track Successfully Edited')
        return redirect(url_for('showTracks', playlist_id=playlist.id))
    else:
        return render_template('edit_track.html', playlist_id=playlist.id,
                               track=editedTrack)

# Delete a track


@app.route('/playlist/<int:playlist_id>/track/<int:track_id>/delete',
           methods=['GET', 'POST'])
@login_required
def deleteTrack(playlist_id, track_id):
    playlist = session.query(Playlist).filter_by(id=playlist_id).one()
    trackToDelete = session.query(Track).filter_by(id=track_id).one()
    if trackToDelete.user_id != login_session['user_id']:
        return "<script>function myFunction() " \
               "{alert('You are not authorized to delete this track. " \
               "Please create your own playlist and track to delete.');" \
               "window.location = '/playlist' }" \
               "</script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(trackToDelete)
        session.commit()
        flash('Track Successfully Deleted')
        return redirect(url_for('showTracks', playlist_id=playlist.id))
    else:
        return render_template('delete_track.html', playlist_id=playlist_id,
                               track=trackToDelete)

# Define User functions


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
