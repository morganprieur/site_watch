
# PREMISE_WATCH 


## Install and launch 

*  Pipenv virtual environment 

Into the terminal, type: 
- `pipenv install`  to install the dependancies 
- `pipenv shell` to launch the virtual environment 


*  The Flask server 

Into the terminal, type: 
- `flask --app=flask_app.py [--debug] run` 
With the `--debug` tag, no need to restart the server while modifying a file. 

*  To stop the server, type `Ctrl+c` 


## Password hash 

Into the flask_app.py: 
    - uncomment the lines `hashed_password = ...` and `print(hashed_password)` 
    - paste the password as an argument of the flask_bcrypt.generate_password_hash method replacing given the example     
to find the hash of the password, 
    - and copy it into the json file. 
    - Comment again the lines. 
For the users, the lines are thoses writen into the `welcome` function. 
For the admins, they are into the `view_premises` function. 
**When modifying a JSON file manually, we must restart the Flask server** 


## Data 

If they are not present, or if you prefer create your own JSON files, follow this format: 

- users.json 
```json 
{"users":[
    {
        "username":"user_01",
        "password":"$2b$12$8/v7/t0s4/7Z3ZEKeyJ2bOBfGdMxWIutJbmDqJR2wVeGh942noGWy"
    },
    {
        "username":"user_02",
        "password":"$2b$12$4oQGmQ6iWTVjFyBKhf1sMepVekTkf3aJSXs3riRPCTh/qWv9lLb/2"
    }
]}
``` 

- admins.json 
```json 
{"admins":[
    {
        "login":"admin_01",
        "password":"$2b$12$RtIPS3GtTGrkJC9/kBGcrOAHBzd0qJ0m80.Kw6cbVvl0m5bIj7MaK"
    },
    {
        "login":"admin_02",
        "password":"$2b$12$zfQk/NOG8r9DrhuNb0nIy.3OGmpRg1cKFl91cIk7SUu5Z6NVxr99O"
    }
]}
``` 

- cameras.json 
```json 
{
    "cameras": [
        {
            "id": "22074",
            "ip": "10.8.0.32"
        },
        {
            "id": "22075",
            "ip": "10.8.0.33"
        }
    ]
}
``` 


