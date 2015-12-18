from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Star
from flask import session as login_session
import random
import string
import requests
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
import os
from flask import make_response
from werkzeug import secure_filename


app = Flask(__name__)

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Category Name Application"

engine = create_engine('sqlite:///categorystarwithuser.db')
Base.metadata.bind = engine

DBsession = sessionmaker(bind=engine)
session = DBsession()

#Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE = state)

@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code, now compatible with Python3
    request.get_data()
    code = request.data.decode('utf-8')
    print "Fuccsvsdvsdfdsfds"
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
    # Submit request, parse response - Python3 compatible
    h = httplib2.Http()
    response = h.request(url, 'GET')[1]
    str_response = response.decode('utf-8')
    result = json.loads(str_response)

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'

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
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        print login_session.get('gplus_id')
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # see if user exists, if it doesn't make a new one
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
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    return output

# User Helper Functions
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


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        # Reset the user's sesson.
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# JSON APIs to view Category Information
@app.route('/category/<int:category_id>/star/JSON')
def categoryMenuJSON(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    stars = session.query(Star).filter_by(
        category_id=category_id).all()
    return jsonify(Star=[i.serialize for i in stars])


@app.route('/category/<int:category_id>/star/<int:star_id>/JSON')
def starJSON(category_id, star_id):
    star = session.query(Star).filter_by(id=star_id).one()
    return jsonify(Star=Menu_Item.serialize)


@app.route('/category/JSON')
def categoriesJSON():
    categories = session.query(Category).all()
    return jsonify(categories=[r.serialize for r in restaurants])


# Show all categories
@app.route('/')
@app.route('/category/')
def showCategories():
    if 'username' not in login_session:
        categories = session.query(Category).order_by(asc(Category.name))
        return render_template('publiccategories.html', categories=categories)
    else:
        categories = session.query(Category).filter_by(user_id = login_session['user_id']).order_by(asc(Category.name))
        return render_template('categories.html', categories=categories)

# Create a new category
@app.route('/category/new/', methods=['GET', 'POST'])
def newCategory():

    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        print login_session['user_id']
        newCategory = Category(name=request.form['name'], user_id=login_session['user_id'])
        session.add(newCategory)
        flash('New Category %s Successfully Created' % newCategory.name)
        session.commit()
        return redirect(url_for('showCategories'))
    else:
        print "login_session"
        return render_template('newCategory.html')


# Edit a category
@app.route('/category/<int:category_id>/edit/', methods=['GET', 'POST'])
def editCategory(category_id):
    editedCategory = session.query(Category).filter_by(id=category_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if editedCategory.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to edit this Category. Please create your own Category in order to edit.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        if request.form['name']:
            editedCategory.name = request.form['name']
            flash('Category Successfully Edited %s' % editedCategory.name)
            return redirect(url_for('showCategories'))
    else:
        return render_template('editCategory.html', category=editedCategory)


# Delete a category
@app.route('/category/<int:category_id>/delete/', methods=['GET', 'POST'])
def deleteCategory(category_id):
    if 'username' not in login_session:
        return redirect('/login')
    categoryToDelete = session.query(Category).filter_by(id=category_id).one()
    if categoryToDelete.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to delete this category. Please create your own category in order to delete.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(categoryToDelete)
        flash('%s Successfully Deleted' % categoryToDelete.name)
        session.commit()
        return redirect(url_for('showCategories', category_id=category_id))
    else:
        return render_template('deleteCategory.html', category=categoryToDelete)

# Show a category star
@app.route('/category/<int:category_id>/')
@app.route('/category/<int:category_id>/star/')
def showStar(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    creator = getUserInfo(category.user_id)
    stars = session.query(Star).filter_by(category_id=category_id).all()
    print "Hello Hu"
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template('publicstar.html', stars=stars, category=category, creator=creator)
    else:
        return render_template('star.html', stars=stars, category=category, creator=creator)


# Create a new star
@app.route('/category/<int:category_id>/star/new/', methods=['GET', 'POST'])
def newStar(category_id):
    if 'username' not in login_session:
        return redirect('/login')
    category = session.query(Category).filter_by(id=category_id).one()
    if login_session['user_id'] != category.user_id:
        return "<script>function myFunction() {alert('You are not authorized to add menu items to this restaurant. Please create your own restaurant in order to add items.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        file = request.files['image']
        filename = secure_filename(file.filename)
        path = url_for('static', filename=filename)
        file.save(os.getcwd()+path)
        newStar = Star(name=request.form['name'], description=request.form['description'], category_id=category_id, user_id=category.user_id, path=path)
        session.add(newStar)
        session.commit()
        flash('New Star %s Item Successfully Created' % (newStar.name))
        return redirect(url_for('showStar', category_id=category_id))
    else:
        return render_template('newstar.html', category_id=category_id)

# Edit a star
@app.route('/category/<int:category_id>/star/<int:star_id>/edit', methods=['GET', 'POST'])
def editStar(category_id, star_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedStar = session.query(Star).filter_by(id=star_id).one()
    category = session.query(Category).filter_by(id=category_id).one()
    if login_session['user_id'] != category.user_id:
        return "<script>function myFunction() {alert('You are not authorized to edit star to this category. Please create your own category in order to edit stars.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        if request.form['name']:
            editedStar.name = request.form['name']
        if request.form['description']:
            editedStar.description = request.form['description']
        if request.form['image']:
            file = request.files['image']
            filename = secure_filename(file.filename)
            path = url_for('static', filename=filename)
            file.save(os.getcwd()+path)
            editedStar.path = path
        session.add(editedStar)
        session.commit()
        flash('Star Successfully Edited.')
        return redirect(url_for('showStar', category_id=category_id))
    else:
        return render_template('editstar.html', category_id=category_id, star_id=star_id, star=editedStar)


# Delete a star
@app.route('/category/<int:category_id>/star/<int:star_id>/delete', methods=['GET', 'POST'])
def deleteStar(category_id, star_id):
    if 'username' not in login_session:
        return redirect('/login')
    category = session.query(Category).filter_by(id=category_id).one()
    starToDelete = session.query(Star).filter_by(id=star_id).one()
    if login_session['user_id'] != category.user_id:
        return "<script>function myFunction() {alert('You are not authorized to delete star to this category. Please create your own category in order to delete stars.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(starToDelete)
        session.commit()
        flash('Star Item Successfully Deleted')
        return redirect(url_for('showStar', category_id=category_id))
    else:
        return render_template('deleteStar.html', star=starToDelete)


if __name__ == "__main__":
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host = '0.0.0.0', port = 5000)
