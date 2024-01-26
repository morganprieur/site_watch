from flask import ( 
    Flask, 
    flash, 
    redirect, 
    url_for, 
    render_template, 
    request, 
    Response 
)
from flask_bcrypt import Bcrypt
import json 
import requests
from requests.auth import HTTPDigestAuth

import os 

# Initialize Flask app
app = Flask(__name__)

# Instanciate Bcrypt 
flask_bcrypt = Bcrypt(app) 


# Camera's actual URL, username, and password 
USERNAME = os.environ.get('USERNAME') 
PASSWORD = os.environ.get('PASSWORD') 


def generate_frame(camera_ip):
    with requests.get( 
        f"http://{camera_ip}:{os.environ.get('PORT')}/{os.environ.get('URI')}", 
        stream=True, 
        auth=digest_auth 
    ) as response:
        if response.status_code == 200:
            bytes_data = bytes()
            for chunk in response.iter_content(chunk_size=1024):
                bytes_data += chunk
                a = bytes_data.find(b'\xff\xd8')  # JPEG start
                b = bytes_data.find(b'\xff\xd9')  # JPEG end
                if a != -1 and b != -1:
                    jpg = bytes_data[a:b + 2]  # Actual JPEG image
                    bytes_data = bytes_data[b + 2:]  # Remaining bytes
                    yield (b'--frame\r\n'
                           b'Content-Type: image/jpeg\r\n\r\n' + jpg + b'\r\n')
        else:
            print("Received unexpected status code {}".format(response.status_code))


# Create the digest auth object
digest_auth = HTTPDigestAuth(USERNAME, PASSWORD)


# For tests:  
# user_02:hash2_for_password
# admin_01:hass_admin1


def loadCameras():
    with open('cameras.json') as c:
        listOfCameras = json.load(c)['cameras']
        return listOfCameras


def loadUsers():
    with open('users.json') as u:
        listOfUsers = json.load(u)['users']
        return listOfUsers


def loadAdmins(): 
    with open('admins.json') as a: 
        listOfAdmins = json.load(a)['admins'] 
        return listOfAdmins 


cameras = loadCameras()
users = loadUsers()
admins = loadAdmins() 


def register_premise(cameras, camera): 
    listOfIds = [] 
    listOfIps = [] 
    message = '' 
    for i in range(len(cameras)): 

        if camera['id'] in cameras[i].values(): 
            listOfIds.append(cameras[i]['id']) 
            message = f'Ce local "{cameras[i]["id"]}" est déjà enregistré.' 
            return message 
        elif camera['ip'] in cameras[i].values(): 
            listOfIps.append(cameras[i]['ip']) 
            message = f'Cette IP "{cameras[i]["ip"]}"  est déjà utilisée.' 
            return message 
    if listOfIds == [] and listOfIps == []: 
        cameras.append(camera)
        new_cameras = {} 
        new_cameras['cameras'] = cameras
        with open('cameras.json', 'w') as c: 
            json.dump(new_cameras, c, indent=4) 
        message = 'Success' 
        return message 


def register_user(users, user): 
    listOfUsernames = [] 
    message = '' 
    for i in range(len(users)): 

        if user['username'] in users[i].values(): 
            listOfUsernames.append(users[i]['username']) 
            message = f'Le username "{users[i]["username"]}" existe déjà.' 
            return message 
    if listOfUsernames == []: 
        users.append(user)
        new_users = {} 
        new_users['users'] = users
        with open('users.json', 'w') as c: 
            json.dump(new_users, c, indent=4) 
        message = 'Success' 
        return message 


def register_admin(admins, admin): 
    listOfLogins = [] 
    message = '' 
    for i in range(len(admins)): 

        if admin['login'] in admins[i].values(): 
            listOfLogins.append(admins[i]['login']) 
            message = f'Le login "{admins[i]["login"]}" existe déjà.' 
            return message 
    if listOfLogins == []: 
        admins.append(admin)
        new_admins = {} 
        new_admins['admins'] = admins 
        with open('admins.json', 'w') as c: 
            json.dump(new_admins, c, indent=4) 
        message = 'Success' 
        return message 


def delete_premise(cameras, camera_id): 
    for i in range(len(cameras)): 
        if camera_id in cameras[i]['id']: 
            cameras.pop(i) 
            break 
    new_cameras = {} 
    new_cameras['cameras'] = cameras 
    with open('cameras.json', 'w') as c: 
        json.dump(new_cameras, c, indent=4) 
    message = 'Success' 
    return message 


def delete_user(users, username): 
    for i in range(len(users)): 
        if username in users[i]['username']: 
            users.pop(i) 
            break 
    new_users = {} 
    new_users['users'] = users 
    with open('users.json', 'w') as c: 
        json.dump(new_users, c, indent=4) 
    message = 'Success' 
    return message 


def delete_admin(admins, admin_login): 
    for i in range(len(admins)): 
        if admin_login in admins[i]['login']: 
            admins.pop(i) 
            break 
    new_admins = {} 
    new_admins['admins'] = admins 
    with open('admins.json', 'w') as c: 
        json.dump(new_admins, c, indent=4) 
    message = 'Success' 
    return message 


# ======== Routes ======== # 
@app.route('/video_feed/<camera_ip>')
def video_feed(camera_ip):
    # print(f"http://{camera_ip}{STREAM_URL}") 
    return Response(generate_frame(camera_ip),
                    mimetype='multipart/x-mixed-replace; boundary=frame')


@app.route('/admin')
def admin(): 
    title = 'Admin login' 
    heading = 'Admin' 
    return render_template('admin.html', title=title, heading=heading)


@app.route('/dashboard', methods=['POST']) 
def dashboard(): 
    title = 'Dashboard' 
    heading = 'Dashboard' 
    message = '' 
    admin = [admin for admin in admins if admin['login'] == request.form['admin']][0] 

    if 'password' in request.form.keys(): 
        is_valid = flask_bcrypt.check_password_hash(admin['password'], request.form['password']) 

        if is_valid: 
            title = 'Dashboard' 
            if not is_valid: 
                message = 'Mauvais login ou mot de passe.' 
                title = 'Login ou mot de passe incorrect' 

    elif ('camera_id' in request.form) and ('camera_ip' in request.form): 
        camera = {} 
        camera['id'] = request.form['camera_id'] 
        camera['ip'] = request.form['camera_ip'] 
        message = register_premise(cameras, camera) 

    elif ('username' in request.form) and ('user_pass' in request.form): 
        user = {} 
        user['username'] = request.form['username'] 
        user['password'] = flask_bcrypt.generate_password_hash(request.form['user_pass']).decode('utf-8') 
        message = register_user(users, user) 

    elif ('new_login' in request.form) and ('new_pass' in request.form): 
        new_admin = {} 
        new_admin['login'] = request.form['new_login'] 
        new_admin['password'] = flask_bcrypt.generate_password_hash(request.form['new_pass']).decode('utf-8') 
        message = register_admin(admins, new_admin) 

    return render_template( 
        'dashboard.html', 
        admin=admin, 
        admins=admins, 
        cameras=cameras, 
        users=users, 
        message=message, 
        title=title, 
        heading=heading 
    ) 


@app.route('/view_premises', methods=['POST'])
def view_premises(): 
    admin = [admin for admin in admins if admin['login'] == request.form['admin']][0] 
    return render_template( 
        'view_premises.html', 
        cameras=cameras, 
        admin=admin, 
    ) 


@app.route('/setup_premise', methods=['POST']) 
def setup_premise(): 
    title = 'Setup premise' 
    heading = 'Ajouter un local' 
    admin = [admin for admin in admins if admin['login'] == request.form['admin']][0] 
    return render_template( 
        'setup_premise.html', 
        cameras=cameras, 
        admin=admin, 
        title=title, 
        heading=heading, 
    ) 


@app.route('/add_user', methods=["POST"]) 
def add_user(): 
    title = 'Add user' 
    heading = 'Ajouter un simple user' 
    admin = [admin for admin in admins if admin['login'] == request.form['admin']][0] 
    return render_template( 
        'add_user.html', 
        admin=admin, 
        title=title, 
        heading=heading, 
    ) 


@app.route('/add_admin', methods=["POST"]) 
def add_admin(): 
    title = 'Add admin' 
    heading = 'Ajouter un admin' 
    admin = [admin for admin in admins if admin['login'] == request.form['admin']][0] 
    return render_template( 
        'add_admin.html', 
        admin=admin, 
        title=title, 
        heading=heading, 
    ) 


@app.route('/delete', methods=['POST']) 
def delete(): 
    title = 'Deleted' 
    heading = 'Success' 
    message = '' 

    admin = [admin for admin in admins if admin['login'] == request.form['admin']][0] 

    if 'camera_id' in request.form.keys(): 
        camera = [camera for camera in cameras if camera['id'] == request.form['camera_id']][0]
        camera_id = camera['id'] 
        message = delete_premise(cameras, camera_id) 
        if message == 'Success': 
            message = f'Le local {camera_id} a bien été supprimé.' 

    elif 'username' in request.form.keys(): 
        user = [user for user in users if user['username'] == request.form['username']][0] 
        username = user['username'] 
        message = delete_user(users, username) 
        if message == 'Success': 
            message = f'L\'utilisateur {username} a bien été supprimé.' 

    elif 'res_admin' in request.form.keys(): 
        res_admin = [admin for admin in admins if admin['login'] == request.form['res_admin']][0] 
        admin_login = res_admin['login'] 
        message = delete_admin(admins, admin_login) 
        if message == 'Success': 
            message = f'L\'admin {admin_login} a bien été supprimé.' 

    return render_template( 
        'delete.html/', 
        admin=admin, 
        message=message, 
        title=title, 
        heading=heading     
    ) 


@app.route('/livestream', methods=['POST'])
def livestream(): 
    if 'admin' in request.form.keys(): 
        admin = [admin for admin in admins if admin['login'] == request.form['admin']][0] 
        camera = [camera for camera in cameras if camera['id'] == request.form['camera_id']][0] 
        return render_template( 
            'livestream.html/', 
            camera=camera, 
            admin=admin, 
        ) 
    elif 'username' in request.form.keys(): 
        user = [user for user in users if user['username'] == request.form['username']][0]
        camera = [camera for camera in cameras if camera['id'] == request.form['camera_id']][0]
        return render_template('livestream.html/', camera=camera, user=user)


@app.route('/')
def index(): 
    title = 'Login' 
    return render_template('index.html', title=title)


@app.route('/welcome', methods=['POST'])
def welcome(): 
    user_list = [] 
    for i in range(len(users)): 
        if request.form['username'] in users[i]['username']: 
            user_list.append(users[i]) 
            is_valid = flask_bcrypt.check_password_hash(user_list[0]['password'], request.form['password']) 
            if is_valid: 
                title = 'Welcome' 
                return render_template('welcome.html/', title=title, user=user_list[0], cameras=cameras) 
            if len(user_list) == 0 or not is_valid: 
                message = 'Mauvais login ou mot de passe.' 
                title = 'Mot de passe incorrect' 
                return render_template('/index.html', title=title, message=message) 


@app.route('/logout_user')
def logout_user():
    return redirect(url_for('index'))


@app.route('/logout_admin')
def logout_admin():
    return redirect(url_for('admin'))


if __name__ == '__main__':
    # file deepcode ignore RunWithDebugTrue: local project 
    app.run(host='0.0.0.0', debug=True)
