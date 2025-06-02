from flask import Flask, request, render_template
import boto3
import bcrypt
from botocore.exceptions import ClientError

app = Flask(__name__)
dynamodb = boto3.resource('dynamodb', region_name='eu-north-1')
table = dynamodb.Table('Users')

@app.route('/', methods=['GET'])
def index():
    return render_template('looks.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']

    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    try:
        table.put_item(
            Item={
                'username': username,
                'password': hashed.decode('utf-8')
            },
            ConditionExpression='attribute_not_exists(username)'
        )
        return render_template('looks.html', message="User registered successfully.")
    except ClientError as e:
        return render_template('looks.html', message="Username already exists.")

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    try:
        response = table.get_item(Key={'username': username})
        user = response.get('Item')

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            return render_template('looks.html', message="Login successful.")
        else:
            return render_template('looks.html', message="Invalid credentials.")
    except ClientError:
        return render_template('looks.html', message="Login error.")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
