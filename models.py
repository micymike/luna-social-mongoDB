from datetime import timedelta, timezone, datetime
import logging
import pytz
from flask_login import UserMixin
from bson.objectid import ObjectId

EAT = timezone(timedelta(hours=3))

# Remove Flask app initialization and mongo
# Instead, create a function to initialize mongo
def init_db(db):
    db = init_db(db)
    logging.debug(f"Database initialized: {db}")
    return db

class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.email = user_data['email']
        self.password_hash = user_data['password_hash']
        self.profile_picture = user_data.get('profile_picture', 'default.jpg')
        self.bio = user_data.get('bio', '')
        self.date_joined = user_data.get('date_joined', datetime.now(pytz.timezone('Africa/Nairobi')))
        self.followed = user_data.get('followed', [])
        self.followers = user_data.get('followers', [])

    def follow(self, user):
        if not self.is_following(user):
            self.followed.append(ObjectId(user.id))
            global db
            db.users.update_one({'_id': ObjectId(self.id)}, {'$push': {'followed': ObjectId(user.id)}})
            db.users.update_one({'_id': ObjectId(user.id)}, {'$push': {'followers': ObjectId(self.id)}})

    def unfollow(self, user):
        if self.is_following(user):
            self.followed.remove(ObjectId(user.id))
            global db
            db.users.update_one({'_id': ObjectId(self.id)}, {'$pull': {'followed': ObjectId(user.id)}})
            db.users.update_one({'_id': ObjectId(user.id)}, {'$pull': {'followers': ObjectId(self.id)}})\
                
    

    def is_following(self, user):
        if isinstance(user, dict):  # Check if user is a dictionary
            user_id = user.get('_id')  # Access the MongoDB ObjectId using '_id'
        else:
            user_id = user.id  # Access the id attribute if user is a User instance
        return ObjectId(user_id) in self.followed

    def __repr__(self):
        return f'<User {self.username}>'

class Post:
    def __init__(self, post_data):
        self.id = str(post_data['_id'])
        self.content = post_data['content']
        self.timestamp = post_data.get('timestamp', datetime.now(EAT))
        self.user_id = post_data['user_id']
        self.media_url = post_data.get('media_url', '')
        self.likes = post_data.get('likes', [])
        self.comments = post_data.get('comments', [])
        self.author = None  # We'll populate this later

    def set_author(self, author):
        self.author = author

    def __repr__(self):
        return f'<Post {self.id}>'

class Like:
    def __init__(self, like_data):
        self.id = str(like_data['_id'])
        self.user_id = like_data['user_id']
        self.post_id = like_data['post_id']

    def __repr__(self):
        return f'<Like {self.id}>'

class Comment:
    def __init__(self, comment_data):
        self.id = str(comment_data['_id'])
        self.content = comment_data['content']
        self.timestamp = comment_data.get('timestamp', datetime.utcnow())
        self.author_id = comment_data['author_id']
        self.post_id = comment_data['post_id']

    def __repr__(self):
        return f'<Comment {self.id}>'

class Message:
    def __init__(self, message_data):
        self.id = str(message_data['_id'])
        self.sender_id = message_data['sender_id']
        self.recipient_id = message_data['recipient_id']
        self.content = message_data['content']
        self.media_url = message_data.get('media_url', '')
        self.timestamp = message_data.get('timestamp', datetime.utcnow())

    def __repr__(self):
        return f'<Message {self.id}>'

EAT = pytz.timezone('Africa/Nairobi')

class Notification:
    def __init__(self, notification_data):
        self.id = str(notification_data['_id'])
        self.user_id = notification_data['user_id']
        self.content = notification_data['content']
        self.timestamp = notification_data.get('timestamp', datetime.now(EAT))
        self.read = notification_data.get('read', False)

    def __repr__(self):
        return f'<Notification {self.id}>'

def create_like_notification(liker_id, post_id, post_author_id):
    # Create a dictionary with the notification data
    notification_data = {
        "user_id": ObjectId(post_author_id),
        "content": f"{db.users.find_one({'_id': ObjectId(liker_id)})['username']} liked your post.",
        "timestamp": datetime.now(EAT),
        "read": False
    }
    
    # Insert the notification data into the database
    result = db.notifications.insert_one(notification_data)
    
    # Create a Notification instance with the data and the generated ID
    notification_data['_id'] = result.inserted_id
    notification = Notification(notification_data)
    
    # Return the Notification instance
    return notification

class Follow:
    def __init__(self, follow_data):
        self.id = str(follow_data['_id'])
        self.follower_id = follow_data['follower_id']
        self.followed_id = follow_data['followed_id']
        self.timestamp = follow_data.get('timestamp', datetime.now(EAT))

    def __repr__(self):
        return f'<Follow {self.id}>'
