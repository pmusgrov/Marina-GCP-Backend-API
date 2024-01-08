from urllib.parse import quote_plus

from google.cloud import datastore
from flask import Flask, request, jsonify, redirect, render_template, session, url_for, make_response
import requests
import constants


from functools import wraps

from six.moves.urllib.request import urlopen
from flask_cors import cross_origin
from jose import jwt


import json
from os import environ as env
from werkzeug.exceptions import HTTPException

from dotenv import load_dotenv, find_dotenv

from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode


app = Flask(__name__)

app.secret_key = 'SECRET_KEY'

client = datastore.Client()

CLIENT_ID = 'Hi0kWj4ej8EPBrN7gJvgOFV5dY8WCLFS'
CLIENT_SECRET = 'Mn2Ydm2JTeTthg3bQzWuxC9ZSkcADCiX8AmTFVsu2K1gmWLV-BWsTWs_acIdsBYr'
DOMAIN = 'dev-ekrbauslpvf2xmh1.us.auth0.com'

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
    server_metadata_url=f'https://' + DOMAIN + '/.well-known/openid-configuration'
)


# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request):

    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                         "description":
                             "Authorization header is missing"}, 401)

    jsonurl = urlopen("https://" + DOMAIN + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                         "description":
                             "Invalid header. "
                             "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                         "description":
                             "Invalid header. "
                             "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://" + DOMAIN + "/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                             "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                             "description":
                                 "incorrect claims,"
                                 " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                             "description":
                                 "Unable to parse authentication"
                                 " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                         "description":
                             "No RSA key in JWKS"}, 401)

# routes /, login, logout, callback, and home.html are taken from auth0 python quickstart
@app.route('/')
def index():
    return render_template("home.html", session=session.get('user'), owner_id=session.get('owner_id'), pretty=json.dumps(session.get('user'), indent=4))

# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload

# Generate a JWT from the Auth0 domain and return it
@app.route('/login', methods=["GET", "POST"])
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )

@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token
    # get the sub value to be used as id for owners(users)
    owner_id = str(token['userinfo']['sub'])

    # Check if the owner already exists
    existing_owner_key = client.key("owners", owner_id)
    existing_owner = client.get(existing_owner_key)

    if not existing_owner:
        # Owner doesn't exist, create a new owner entity
        new_owner = datastore.Entity(key=existing_owner_key)
        new_owner.update({
            "owner_id": owner_id,
            "boats": []
        })
        # add owner
        client.put(new_owner)
        # Return a JSON response with a 201 status code for successful creation
        response_data = {"message": "Owner created successfully", "owner_id": owner_id}
        status_code = 201

    else:
        # Owner already exists, return a JSON response with a 400 status code
        response_data = {"message": "Owner already exists", "owner_id": owner_id}
        status_code = 400

    # Create a JSON response with the appropriate status code
    response = make_response(jsonify(response_data), status_code)
    # send owner_id to be displayed to user
    session["owner_id"] = owner_id
    return redirect("/")

def get_numeric_sub(sub):
    # Extract the numeric part from the sub value
    numbers = ''.join(sub.split('|')[1:])
    return numbers

@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://" + DOMAIN
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("index", _external=True),
                "client_id": CLIENT_ID,
            },
            quote_via=quote_plus,
        )

    )

@app.route("/owners", methods=["GET"])
def get_post_owners():
    if request.method == 'GET':
        # check to see if response will be in json
        if 'application/json' in request.accept_mimetypes:

            owners = []

            # query for all the desired Entities
            query = client.query(kind=constants.owners)

            # iterate through query and grab info
            for e in query.fetch():
                owner_info = {
                    'owner_id': e.get('owner_id'),
                    'boats': e.get('boats'),
                }
                owners.append(owner_info)
            # Return 200 status code and the array of owners
            return jsonify(owners), 200

        else:
             return ('Request type not acceptable', 406)
    else:
        return 'Method not recognized', 405

@app.route('/boats', methods=['POST','GET'])
def boats_get_post():
    if request.method == 'POST':
        # check to see if response will be in json
        if 'application/json' in request.accept_mimetypes:
            payload = verify_jwt(request)
            # get content from request
            content = request.get_json()
            # get root URL from request
            url = request.url
            # check if all required attributes exist in the request, if not return 400
            if "name" not in content or "type" not in content or "length" not in content:
                error = "The request object is missing at least one of the required attributes"
                return jsonify({'Error': error}), 400
            #  if all attributes exist, create new boat and return new_boat with 201
            else:
                new_boat = datastore.entity.Entity(key=client.key(constants.boats))
                new_boat.update({"name": content["name"], "type": content["type"], "length": content["length"], "loads":[],  "owner": payload["sub"]})
                # add new id to object
                client.put(new_boat)

                new_boat.update({"id": new_boat.key.id})
                client.put(new_boat)
                # generate self link
                new_boat.update(({"self": url + str('/') + str(new_boat.key.id)}))
                return jsonify(new_boat), 201
        else:
            return ('Request type not acceptable', 406)

    # if GET request to get all boats, return all boats
    elif request.method == 'GET':
        # check to see if response will be in json
        if 'application/json' in request.accept_mimetypes:
            payload = verify_jwt(request)
            # query for all the desired Entities
            query = client.query(kind=constants.boats)
            # narrow query based on parameters, couldn't fix error in time
            query.add_filter('owner', '=', payload["sub"])
            total_count = len(list(query.fetch()))
            # set limit and offsets
            q_limit = int(request.args.get('limit', '5'))
            q_offset = int(request.args.get('offset', '0'))
            # create iterator to section Entities
            l_iterator = query.fetch(limit=q_limit, offset=q_offset)
            pages = l_iterator.pages
            results = list(next(pages))
            # use next page token to determine next url needed
            if l_iterator.next_page_token:
                next_offset = q_offset + q_limit
                next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
            else:
                next_url = None
            # create array to store cleaned results
            actual_results = []
            for e in results:
                # check if instance is an actual Entity
                if isinstance(e, datastore.Entity):
                    e["id"] = e.key.id
                    # generate self attribute
                    e["self"] = (request.base_url + '/' + str(e.id))
                    actual_results.append(e)
            # json style output
            output = {"boats": actual_results, "total_count": total_count}
            # append next url
            if next_url:
                output["next"] = next_url
            # return json object making sure it is in correct format with default
            return json.dumps(output, default=str)
        else:
            return ('Request type not acceptable', 406)
    else:
        return 'Method not recognized', 405

@app.route('/boats/<id>', methods=['PUT','DELETE', 'GET', 'PATCH'])
def boats_put_delete(id):
    if request.method == 'PUT':
        # check to see if response will be in json
        if 'application/json' in request.accept_mimetypes:
            payload = verify_jwt(request)
            # get content from request
            content = request.get_json()

            # check if all required attributes exist in the request, if not return 400
            if "name" not in content or "type" not in content or "length" not in content:
                error = "The request object is missing at least one of the required attributes"
                return jsonify({'Error': error}), 400

            # get boat key using id and get boat
            boat_key = client.key(constants.boats, int(id))
            boat = client.get(key=boat_key)

            # check if a boat exists
            if json.dumps(boat) == 'null':
                error = "No boat with this boat_id exists"
                return jsonify({'Error': error}), 404

            # Check if the owner of the boat matches the owner in the JWT
            if payload['sub'] != boat.get('owner'):
                error = "Someone else owns that boat"
                return jsonify({'error': error}), 403

            # update boat and put into server, return new boat
            boat.update({"name": content["name"], "type": content["type"], "length": content["length"]})
            client.put(boat)
            return json.dumps(boat),200
        else:
            return ('Request type not acceptable', 406)

    elif request.method == 'DELETE':
        # get object key and object from passed argument
        payload = verify_jwt(request)
        key = client.key(constants.boats, int(id))
        boat = client.get(key=key)
        # check if a boat exists
        if boat is None:
            error = "No boat with this boat_id exists"
            return jsonify({'Error': error}), 404

        # query for objects and put into list
        query = client.query(kind=constants.loads)
        results = list(query.fetch())

        if payload['sub'] != boat.get('owner'):
            error = "Someone else owns that boat"
            return jsonify({'error': error}), 403

        # iterate through list for desired attribute

        for e in results:
            current_carrier = e.get("carrier")
            # check if object is an actual Entity and if an id exists
            if isinstance(current_carrier, datastore.Entity):
                if current_carrier['id'] is not None:
                    # if attribute matches object id, set to none and update data
                    if boat.id == current_carrier['id']:
                        load_key = client.key(constants.loads, int(e['id']))
                        load = client.get(key=load_key)
                        load['carrier'] = None
                        client.put(load)

        client.delete(key)
        return '', 204

    elif request.method == 'GET':
        # check to see if response will be in json
        if 'application/json' in request.accept_mimetypes:
            payload = verify_jwt(request)
            url = request.url
            # get boat key using id and get boat
            boat_key = client.key(constants.boats, int(id))
            boat = client.get(key=boat_key)
            # check if a boat exists
            if json.dumps(boat) == 'null':
                error = "No boat with this boat_id exists"
                return jsonify({'Error': error}), 404
            elif payload['sub'] != boat.get('owner'):
                error = "Someone else owns that boat"
                return jsonify({'error': error}), 403
            # return boat if it does exist
            else:
                boat["self"] = url
                return json.dumps(boat), 200
        else:
            return ('Request type not acceptable', 406)

    elif request.method == 'PATCH':
        if 'application/json' in request.accept_mimetypes:
            payload = verify_jwt(request)
            # get content from request
            content = request.get_json()

            if "id" in content:
                error = "You may not update the id of a boat"
                return jsonify({'Error': error}), 403

            # check if all required attributes exist in the request, if not return 400
            if "name" not in content and "type" not in content and "length" and content:
                error = "You must include an attribute to update"
                return jsonify({'Error': error}), 400


            # check if any extra attributes exist, if so return 400
            allowed_attributes = ["name", "type", "length"]
            for a in content:
                if a not in allowed_attributes:
                    error = "You have one or more incorrect attributes"
                    return jsonify({'Error': error}), 400

            # validate that name and type attributes are strings and length is int
            if "name" in content:
                if not isinstance(content['name'], str):
                    error = "One of the attributes is an incorrect datatype"
                    return jsonify({'Error': error}), 400

            if "type" in content:
                if not isinstance(content['type'], str):
                    error = "One of the attributes is an incorrect datatype"
                    return jsonify({'Error': error}), 400

            if "length" in content:
                if not isinstance(content['length'], int):
                    error = "One of the attributes is an incorrect datatype"
                    return jsonify({'Error': error}), 400

            # get boat key using id and get boat
            boat_key = client.key(constants.boats, int(id))
            boat = client.get(key=boat_key)

            # check if new name would be unique
            query = client.query(kind=constants.boats)
            results = list(query.fetch())
            if "name" in content and content["name"] != boat["name"]:
                for e in results:
                    if e["name"] == content["name"]:
                        error = "That name is already in use"
                        return jsonify({'Error': error}), 403

            # check if a boat exists
            if json.dumps(boat) == 'null':
                error = "No boat with this boat_id exists"
                return jsonify({'Error': error}), 404

            # Check if the owner of the boat matches the owner in the JWT
            if payload['sub'] != boat.get('owner'):
                error = "Someone else owns that boat"
                return jsonify({'error': error}), 403

            # update boat and put into server, return new boat
            for key, value in content.items():
                if key in allowed_attributes:
                    boat[key] = value
            client.put(boat)

            # set status code
            return ('Update Succesful', 204)
        else:
            return ('Request type not acceptable', 406)
    else:
        return 'Method not recognized', 405

@app.route('/boats/<bid>/loads/<lid>', methods=['PUT','DELETE'])
def add_delete_reservation(bid,lid):
    if request.method == 'PUT':
        # check to see if response will be in json
        if 'application/json' in request.accept_mimetypes:
            payload = verify_jwt(request)
            # grab URL boat and load
            url = request.root_url
            boat_key = client.key(constants.boats, int(bid))
            boat = client.get(key=boat_key)
            load_key = client.key(constants.loads, int(lid))
            load = client.get(key=load_key)
            # check if a boat/load exists
            if boat is None or load is None:
                error = "The specified boat and/or load does not exist"
                return jsonify({'Error': error}), 404
            elif payload['sub'] != boat.get('owner'):
                error = "Someone else owns that boat"
                return jsonify({'error': error}), 403
            # check if load is already on a boat
            load_carrier = load.get('carrier')
            if load_carrier is not None:
                error = "The load is already loaded on another boat"
                return jsonify({'Error': error}), 403
            # set/return selfs
            load_url = (url + 'loads' + '/' + str(load.id))
            boat_url = (url + 'boats' + '/' + str(boat.id))
            load['self'] = load_url
            boat['self'] = boat_url
            # json style data for new Entities
            boat_data = {"id": boat.id, "self": boat_url}
            load['carrier'] = boat_data
            load_data = {"id": load.id, "self": load_url}
            # check if boat has load(s) already and update correctly
            if 'loads' in boat.keys():
                boat['loads'].append(load_data)
            else:
                boat['loads'] = [load_data]
            # update carrier attribute for load and update load and boat
            client.put(boat)
            client.put(load)
            return('',204)
        else:
            return ('Request type not acceptable', 406)

    elif request.method == 'DELETE':
        # get boat and load
        payload = verify_jwt(request)
        boat_key = client.key(constants.boats, int(bid))
        boat = client.get(key=boat_key)
        load_key = client.key(constants.loads, int(lid))
        load = client.get(key=load_key)
        # check if boat/load exists
        if boat is None or load is None:
            error = "No boat with this boat_id is loaded with the load with this load_id"
            return jsonify({'Error': error}), 404
        elif payload['sub'] != boat.get('owner'):
            error = "Someone else owns that boat"
            return jsonify({'error': error}), 403
        # if another Entity exists that needs to updated, look for instances and do so
        if 'loads' in boat.keys():
            for ids in boat['loads']:
                if ids['id'] == int(lid):
                    boat['loads'].remove(ids)
                    load['carrier'] = None
                    client.put(boat)
                    client.put(load)
                    return('',204)
            error = "No boat with this boat_id is loaded with the load with this load_id"
            return jsonify({'Error': error}), 404
        else:
            error = "No boat with this boat_id is loaded with the load with this load_id"
            return jsonify({'Error': error}), 404
    else:
        return 'Method not recognized', 405

@app.route('/loads', methods=['POST','GET'])
def loads_get_post():
    if request.method == 'POST':
        # check to see if response will be in json
        if 'application/json' in request.accept_mimetypes:
            # get content from request
            content = request.get_json()
            # get root URL from request
            url = request.url
            # check if all required attributes exist in the request, if not return 400
            if "volume" not in content or "item" not in content or "creation_date" not in content:
                error = "The request object is missing at least one of the required attributes"
                return jsonify({'Error': error}), 400
            #  if all attributes exist, create new load and return new_load with 201
            else:
                new_load = datastore.entity.Entity(key=client.key(constants.loads))
                new_load.update({"volume": content["volume"], "item": content["item"], "creation_date": content["creation_date"]})
                client.put(new_load)

                # add new id to object and carrier set to None
                new_load.update({"id": new_load.key.id})
                new_load.update(({"carrier": None}))
                client.put(new_load)
                # generate self link
                new_load.update(({"self": url + str('/') + str(new_load.key.id)}))
                return jsonify(new_load), 201
        else:
            return ('Request type not acceptable', 406)
    elif request.method == 'GET':
        # check to see if response will be in json
        if 'application/json' in request.accept_mimetypes:
            # query for all the desired Entities
            query = client.query(kind=constants.loads)
            total_count = len(list(query.fetch()))
            # set limit and offsets
            q_limit = int(request.args.get('limit', '5'))
            q_offset = int(request.args.get('offset', '0'))
            # create iterator to section Entities
            g_iterator = query.fetch(limit=q_limit, offset=q_offset)
            pages = g_iterator.pages
            results = list(next(pages))
            # use next page token to determine next url needed
            if g_iterator.next_page_token:
                next_offset = q_offset + q_limit
                next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
            else:
                next_url = None
            # create array to store cleaned results
            actual_results = []
            for e in results:
                # check if instance is an actual Entity
                if isinstance(e, datastore.Entity):
                    e["id"] = e.key.id
                    # generate self attribute
                    e["self"] = (request.base_url + '/' + str(e.id))
                    actual_results.append(e)
            # json style output
            output = {"loads": actual_results, "total_count": total_count}
            # append next url
            if next_url:
                output["next"] = next_url
            # return json object making sure it is in correct format with default
            return json.dumps(output, default=str)
        else:
            return ('Request type not acceptable', 406)
    else:
        return 'Method not recognized', 405

@app.route('/loads/<id>', methods=['PUT','DELETE', 'GET', 'PATCH'])
def loads_put_delete(id):
    # check to see if response will be in json
    if request.method == 'PUT':
        if 'application/json' in request.accept_mimetypes:
            # get content from request
            content = request.get_json()

            # check if all required attributes exist in the request, if not return 400
            if "volume" not in content or "item" not in content or "creation_date" not in content:
                error = "The request object is missing at least one of the required attributes"
                return jsonify({'Error': error}), 400

            # get load key using id and get load
            load_key = client.key(constants.loads, int(id))
            load = client.get(key=load_key)

            # check if a load exists
            if json.dumps(load) == 'null':
                error = "No load with this load_id exists"
                return jsonify({'Error': error}), 404

            # update load and put into server, return new load
            load.update({"volume": content["volume"], "item": content["item"], "creation_date": content["creation_date"]})
            client.put(load)
            return json.dumps(load),200
        else:
            return ('Request type not acceptable', 406)

    elif request.method == 'DELETE':
        # get object key and object from passed argument
        key = client.key(constants.loads, int(id))
        load = client.get(key=key)
        # check if a load exists
        if load is None:
            error = "No load with this load_id exists"
            return jsonify({'Error': error}), 404

        # query for objects and put into list
        query = client.query(kind=constants.boats)
        results = list(query.fetch())
        # iterate through list for desired attribute
        for e in results:
            current_load = e.get("loads")
            # if attribute matches object id, set to none and update data
            if current_load is not None:
                for loads in current_load:
                    # check if it is an actual Entity
                    if isinstance(loads, datastore.Entity):
                        if load.id == loads['id']:
                            current_load.remove(loads)
                            client.put(e)
        client.delete(key)
        return '', 204


    elif request.method == 'GET':
        # check to see if response will be in json
        if 'application/json' in request.accept_mimetypes:
            url = request.url
            # get load key using id and get load
            load_key = client.key(constants.loads, int(id))
            load = client.get(key=load_key)
            # check if a load exists
            if json.dumps(load) == 'null':
                error = "No load with this load_id exists"
                return jsonify({'Error': error}), 404
            # return load if it does exist
            else:
                load["self"] = (url)
                return json.dumps(load), 200
        else:
            return ('Request type not acceptable', 406)

    elif request.method == 'PATCH':
        if 'application/json' in request.accept_mimetypes:

            # get content from request
            content = request.get_json()

            if "id" in content:
                error = "You may not update the id of a boat"
                return jsonify({'Error': error}), 403

            # check if all required attributes exist in the request, if not return 400
            if "volume" not in content and "item" not in content and "creation_date" and content:
                error = "You must include an attribute to update"
                return jsonify({'Error': error}), 400

            # check if any extra attributes exist, if so return 400
            allowed_attributes = ["volume", "item", "creation_date"]
            for a in content:
                if a not in allowed_attributes:
                    error = "You have one or more incorrect attributes"
                    return jsonify({'Error': error}), 400

            # validate that volume, item, and creation_date attributes are strings
            if "volume" in content:
                if not isinstance(content['volume'], str):
                    error = "One of the attributes is an incorrect datatype"
                    return jsonify({'Error': error}), 400

            if "item" in content:
                if not isinstance(content['item'], str):
                    error = "One of the attributes is an incorrect datatype"
                    return jsonify({'Error': error}), 400

            if "creation_date" in content:
                if not isinstance(content['creation_date'], str):
                    error = "One of the attributes is an incorrect datatype"
                    return jsonify({'Error': error}), 400

            # get load key using id and get load
            load_key = client.key(constants.loads, int(id))
            load = client.get(key=load_key)

            # check if a load exists
            if json.dumps(load) == 'null':
                error = "No boat with this boat_id exists"
                return jsonify({'Error': error}), 404

            # update ,oad and put into server, return new load
            for key, value in content.items():
                if key in allowed_attributes:
                    load[key] = value
            client.put(load)

            # set status code
            return ('Update Succesful', 204)
        else:
            return ('Request type not acceptable', 406)
    else:
        return 'Method not recognized', 405

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
