#!/usr/bin/env python
from flask import Flask, jsonify, redirect, render_template
from flask import request, url_for, make_response, flash
from flask import session as login_session
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from catalog import Base, Category, Item, User
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import random
import string
import httplib2
import json
import requests


app = Flask(__name__, static_url_path='/static')
CLIENT_SECRETS = json.loads(open('client_secrets.json', 'r').read())
CLIENT_ID = CLIENT_SECRETS['web']['client_id']
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBsession = sessionmaker(bind=engine)
session = DBsession()


@app.route('/', methods=['GET'])
@app.route('/catalog', methods=['GET'])
def getCatalog():
    if(request.method == 'GET'):
        categories = session.query(Category).all()
        return render_template('catalog.html', categories=categories)


@app.route('/catalog/new', methods=['GET', 'POST'])
def newCategory():
    if(not checkLoggedIn()):
        flash("Must login to access this functionality")
        return redirect(url_for('login'))
    if(not checkTokenValid()):
        flash("Login session expired")
        return redirect(url_for('logout'))
    if(request.method == 'GET'):
        return render_template('newcategory.html')
    if(request.method == 'POST'):
        newCatName = request.form['name']
        category = session.query(Category).filter_by(name=newCatName).first()
        if((newCatName is None) or (newCatName == '')):
            flash("New category must have a valid name")
            return redirect(url_for('newCategory'))
        elif(category is not None):
            flash("New category must have a unique name")
            return redirect(url_for('newCategory'))
        else:
            newCat = Category(name=newCatName, user_id=login_session['id'])
            session.add(newCat)
            session.commit()
            flash(newCatName + " category has been created")
            return redirect(url_for('getCatalog'))


@app.route('/catalog/<int:category_id>', methods=['GET'])
def getCategory(category_id):
    if(request.method == 'GET'):
        category = session.query(Category).filter_by(id=category_id).first()
        items = session.query(Item).filter_by(cat_id=category_id).all()
        return render_template('category.html', category=category, items=items)


@app.route('/catalog/<int:category_id>/edit', methods=['GET', 'POST'])
def editCategory(category_id):
    if(not checkLoggedIn()):
        flash("Must login to access this functionality")
        return redirect('/login')
    if(not checkTokenValid()):
        flash("Login session expired")
        return redirect(url_for('logout'))
    category = session.query(Category).filter_by(id=category_id).first()
    if(category.user_id != login_session['id']):
        flash("Insufficient Priviledges")
        return redirect(url_for('getCategory', category_id=category_id))
    if(request.method == 'GET'):
        return render_template('editcategory.html', category=category)
    if(request.method == 'POST'):
        editCatName = request.form['name']
        catCheck = session.query(Category).filter_by(name=editCatName).first()
        if((editCatName is None) or (editCatName == '')):
            flash("Editted category must have a valid name")
            return redirect(url_for('editCategory', category_id=category_id))
        elif(catCheck is not None):
            flash("Editted category must have a unique name")
            return redirect(url_for('editCategory', category_id=category_id))
        else:
            category.name = editCatName
            session.add(category)
            session.commit()
            flash(editCatName + " category has been editted")
            return redirect(url_for('getCategory', category_id=category_id))


@app.route('/catalog/<int:category_id>/delete', methods=['GET', 'POST'])
def deleteCategory(category_id):
    if(not checkLoggedIn()):
        flash("Must login to access this functionality")
        return redirect('/login')
    if(not checkTokenValid()):
        flash("Login session expired")
        return redirect(url_for('logout'))
    category = session.query(Category).filter_by(id=category_id).first()
    if(category.user_id != login_session['id']):
        flash("Insufficient Priviledges")
        return redirect(url_for('getCategory', category_id=category_id))
    if(request.method == 'GET'):
        return render_template('deletecategory.html', category=category)
    if(request.method == 'POST'):
        items = session.query(Item).filter_by(cat_id=category_id).all()
        if (items is not None):
            for item in items:
                session.delete(item)
        session.delete(category)
        session.commit()
        flash(category.name + ''' category has been deleted
             along with all items''')
        return redirect(url_for('getCatalog'))


@app.route('/catalog/<int:category_id>/new', methods=['GET', 'POST'])
def newItem(category_id):
    if(not checkLoggedIn()):
        flash("Must login to access this functionality")
        return redirect('/login')
    if(not checkTokenValid()):
        flash("Login session expired")
        return redirect(url_for('logout'))
    category = session.query(Category).filter_by(id=category_id).first()
    if(category.user_id != login_session['id']):
        flash("Insufficient Priviledges")
        return redirect(url_for('getCategory', category_id=category_id))
    if(request.method == 'GET'):
        return render_template('newitem.html', category=category)
    if(request.method == 'POST'):
        newItemTitle = request.form['title']
        newItemDesc = request.form['description']
        if((newItemTitle is None) or (newItemTitle == '')):
            flash("New item must have a valid title")
            return redirect(url_for('newItem', category_id=category_id))
        else:
            newItem = Item(title=newItemTitle, description=newItemDesc,
                           category=category, user_id=login_session['id'])
            session.add(newItem)
            session.commit()
            flash(newItemTitle + " item has been created")
            return redirect(url_for('getCategory', category_id=category_id))


@app.route('/catalog/<category_id>/<item_id>', methods=['GET'])
def getItem(category_id, item_id):
    if(request.method == 'GET'):
        category = session.query(Category).filter_by(id=category_id).first()
        item = session.query(Item).filter_by(id=item_id).first()
        return render_template('item.html', item=item, category=category)


@app.route('/catalog/<category_id>/<item_id>/edit', methods=['GET', 'POST'])
def editItem(category_id, item_id):
    if(not checkLoggedIn()):
        flash("Must login to access this functionality")
        return redirect('/login')
    if(not checkTokenValid()):
        flash("Login session expired")
        return redirect(url_for('logout'))
    item = session.query(Item).filter_by(id=item_id).first()
    if(item.user_id != login_session['id']):
        flash("Insufficient Priviledges")
        return redirect(url_for('getItem', category_id=category_id,
                        item_id=item_id))
    if(request.method == 'GET'):
        return render_template('edititem.html', item=item)
    if(request.method == 'POST'):
        editItemTitle = request.form['title']
        editItemDesc = request.form['description']
        if((editItemTitle is None) or (editItemTitle == '')):
            flash("Editted item must have a valid title")
            return redirect(url_for('editItem', category_id=item.cat_id,
                                    item_id=item_id))
        else:
            item.title = editItemTitle
            item.description = editItemDesc
            session.add(item)
            session.commit()
            flash(editItemTitle + " item has been editted")
            return redirect(url_for('getItem', category_id=item.cat_id,
                                    item_id=item_id))


@app.route('/catalog/<category_id>/<item_id>/delete', methods=['GET', 'POST'])
def deleteItem(category_id, item_id):
    if(not checkLoggedIn()):
        flash("Must login to access this functionality")
        return redirect('/login')
    if(not checkTokenValid()):
        flash("Login session expired")
        return redirect(url_for('logout'))
    item = session.query(Item).filter_by(id=item_id).first()
    if(item.user_id != login_session['id']):
        flash("Insufficient Priviledges")
        return redirect(url_for('getItem', category_id=category_id,
                                item_id=item_id))
    if(request.method == 'GET'):
        return render_template('deleteitem.html', item=item)
    if(request.method == 'POST'):
        session.delete(item)
        session.commit()
        flash(item.title + " item has been deleted")
        return redirect(url_for('getCategory', category_id=item.cat_id))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if(checkLoggedIn()):
        flash("Already logged in as " + login_session['username'])
        return redirect(url_for('getCatalog'))
    if(request.method == 'GET'):
        state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                        for x in xrange(32))
        login_session['state'] = state
        return render_template('login.html', state=state)
    if(request.method == 'POST'):
        username = request.form['username']
        password = request.form['password']
        user = session.query(User).filter_by(username=username).first()
        if((user is not None) and (user.verify_password(password)
                                   is not None)):
            login_session['username'] = username
            login_session['id'] = user.id
            login_session['email'] = user.email
            login_session['access_token'] = user.get_auth_token()
            login_session['provider'] = 'local_server'
            flash("Logged in as " + username)
            return redirect(url_for('getCatalog'))
        else:
            flash("Invalid username/password")
            return redirect(url_for('login'))


@app.route('/logout', methods=['GET'])
def logout():
    if(not checkLoggedIn()):
        flash("Must login to access this functionality")
        return redirect('/login')
    if(login_session['provider'] == 'google'):
        urlBase = 'https://accounts.google.com/'
        urlLocation = 'o/oauth2/revoke?token='
        access_token = login_session['access_token']
        url = urlBase + urlLocation + access_token
        h = httplib2.Http()
        result = h.request(url, 'GET')[0]
        if (result['status'] == '200'):
            del login_session['gplus_id']
        else:
            response = make_response(json.dumps('''Failed to revoke token
             for given user.''', 400))
            response.headers['Content-Type'] = 'application/json'
            return response
    del login_session['provider']
    del login_session['username']
    del login_session['email']
    del login_session['access_token']
    flash("Logout successful")
    return redirect(url_for('login'))


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate anti-forgery state token
    if (request.args.get('state') != login_session['state']):
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
        response = make_response(json.dumps('''Failed to upgrade the
         authorization code.'''), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    urlBase = 'https://www.googleapis.com/'
    urlLocation = 'oauth2/v1/tokeninfo?access_token='
    access_token = credentials.access_token
    url = urlBase + urlLocation + access_token
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(json.dumps('''Token's user ID doesn't
         match given user ID.'''), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps('''Token's client ID does not
         match app's.'''), 401)
        print ("sToken's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the current user isn't already logged in
    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('''Current user is already
         connected.'''), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = answer.json()
    login_session['provider'] = 'google'
    login_session['username'] = data['name']
    login_session['email'] = data['email']
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # See if user exists. IF not, create user
    user = session.query(User).filter_by(email=data["email"]).first()
    if (user is None):
        user = User(username=login_session['username'],
                    email=login_session['email'])
        session.add(user)
        session.commit()
    login_session['id'] = user.id
    flash("Logged in as " + data['name'])
    return "Login Successful"


@app.route('/new_user', methods=['GET', 'POST'])
def newUser():
    if(request.method == 'GET'):
        return render_template('newuser.html')
    if(request.method == 'POST'):
        newUsername = request.form['username']
        newPassword = request.form['password']
        newEmail = request.form['email']
        if((newUsername is None) or (newUsername == '') or
                (newPassword is None) or (newPassword == '')):
            flash("New user must have a valid username/password")
            return redirect(url_for('newUser'))
        else:
            user = session.query(User).filter_by(username=newUsername).first()
            if (user is None):
                newUser = User(username=newUsername, email=newEmail)
                newUser.set_hash_password(newPassword)
                session.add(newUser)
                session.commit()
                flash("New user created")
                return redirect(url_for('login'))
            else:
                flash("Username already in use")
                return redirect(url_for('newUser'))


@app.route('/catalog/json', methods=['GET'])
def getCatalogJson():
    catalogList = []
    categories = session.query(Category).all()
    for category in categories:
        catalogJson = category.serialize
        items = session.query(Item).filter_by(cat_id=category.id)
        catalogJson["Items"] = [item.serialize for item in items]
        catalogList.append(catalogJson)
    return jsonify(Category=catalogList)


@app.route('/catalog/<category_id>/json', methods=['GET'])
def getCategoryJson(category_id):
    categoryList = []
    category = session.query(Category).filter_by(id=category_id).first()
    categoryJson = category.serialize
    items = session.query(Item).filter_by(cat_id=category_id)
    categoryJson["items"] = [item.serialize for item in items]
    categoryList.append(categoryJson)
    return jsonify(Category=categoryList)


@app.route('/catalog/<category_id>/<item_id>/json', methods=['GET'])
def getItemJson(category_id, item_id):
    itemList = []
    item = session.query(Item).filter_by(id=item_id).first()
    itemJson = item.serialize
    itemList.append(itemJson)
    return jsonify(item=itemList)


def checkLoggedIn():
    if ('username' not in login_session):
        return False
    return True


def checkTokenValid():
    if (not checkLoggedIn()):
        return False
    if (login_session['provider'] == 'local_server'):
        user_id = User.verify_auth_token(login_session['access_token'])
        if (user_id is None):
            return False
    return True


if (__name__ == '__main__'):
    app.debug = True
    app.secret_key = 'super_secret'
    app.run(host='0.0.0.0', port=5000, threaded=False)
