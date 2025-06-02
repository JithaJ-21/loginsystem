import boto3
import bcrypt

# Initialize DynamoDB resource
dynamodb = boto3.resource('dynamodb', region_name='eu-north-1')
table = dynamodb.Table('Users')

# Function to add a new user
def signup(username, password):
    # Hash the password before storing
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Store user credentials in DynamoDB
    try:
        table.put_item(
            Item={
                'username': username,
                'password': hashed.decode('utf-8')
            },
            ConditionExpression='attribute_not_exists(username)'  # Avoid overwriting
        )
        print("User registered successfully.")
    except Exception as e:
        print("User already exists or error:", e)

# Function to validate login
def login(username, password):
    try:
        response = table.get_item(Key={'username': username})
        user = response.get('Item')

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            print("Login successful.")
            return True
        else:
            print("Invalid credentials.")
            return False
    except Exception as e:
        print("Login error:", e)
        return False

# Example usage
signup('jitha_user', 'mypassword123')         # Run once to register
login('jitha_user', 'mypassword123')          # Validate login
login('jitha_user', 'wrongpassword')          # Invalid login
