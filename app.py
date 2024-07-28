
import json
import logging
import re
import os
from bson.objectid import ObjectId
import emojis
from flask import Flask, abort, render_template, request, jsonify, redirect, url_for, flash, session
from flask_pymongo import DESCENDING, PyMongo
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
import pymongo
import pytz
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit, join_room, leave_room
import google.generativeai as genai
from dotenv import load_dotenv
from datetime import datetime, timedelta
from sqlalchemy import or_, case
#from mess import init_mess
from models import User, Post, Comment, Like, Message, Notification, Follow, init_db
from prof import profile as profile_blueprint

load_dotenv()
app = Flask(__name__)
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi

uri = "mongodb+srv://mikemoses:mikemoses@cluster0.jvbhvc3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"


# Create a new client and connect to the server
client = MongoClient(uri, server_api=ServerApi('1'))

# Send a ping to confirm a successful connection
try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)

# Create a database object
db = client.get_database('your_database_name')  # Replace 'your_database_name' with your actual database name

app.config['SECRET_KEY'] = os.urandom(24).hex()
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max-limit
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)  # Set session to last for 30 days

# Initialize MongoDB

login_manager = LoginManager(app)
login_manager.login_view = 'login'
socketio = SocketIO(app)


genai.configure(api_key=os.getenv('GEMINI_API_KEY'))
model = genai.GenerativeModel('gemini-pro')

@login_manager.user_loader
def load_user(user_id):
    user = db.users.find_one({"_id": ObjectId(user_id)})
    if user:
        return User(user)
    return None
# Register blueprints
app.register_blueprint(profile_blueprint)


def is_valid_input(text):
    return text and len(text.strip()) > 0

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif', 'mp4'}

from flask_login import current_user, login_required

@app.route('/')
def index():
    if current_user.is_authenticated:
        all_users = db.users.find()
        all_posts = db.posts.find().sort("timestamp", -1)
        
        all_posts_list = []
        for post in all_posts:
            post_obj = Post(post)
            author = db.users.find_one({"_id": ObjectId(post_obj.user_id)})
            if author:
                post_obj.set_author(User(author))
            post_obj.comment_count = len(post.get('comments', []))
            all_posts_list.append(post_obj)
    else:
        all_users = []
        all_posts_list = []

    return render_template('index.html', all_users=all_users, all_posts=all_posts_list)

@app.route('/login', methods=['GET', 'POST'])
def login():
    logging.debug("Entering login function")
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        logging.debug(f"Login attempt for username: {username}")

        try:
            user = db.users.find_one({"username": username})
            logging.debug(f"User found: {user is not None}")

            if user and check_password_hash(user['password_hash'], password):
                user_obj = User(user)
                login_user(user_obj)
                logging.info(f"User {username} logged in successfully")
                flash('Logged in successfully.', 'success')
                return redirect(url_for('index'))
            else:
                logging.warning(f"Failed login attempt for username: {username}")
                flash('Invalid username or password', 'error')
        except Exception as e:
            logging.error(f"Error during login process: {str(e)}")
            flash('An error occurred. Please try again later.', 'error')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    logging.debug("Entering register function")
    if request.method == 'POST':
        hashed_password = generate_password_hash(request.form['password'])
        new_user = {
            "username": request.form['username'],
            "email": request.form['email'],
            "password_hash": hashed_password,
            "date_joined": datetime.now(pytz.timezone('Africa/Nairobi'))
        }
        logging.debug(f"Attempting to insert new user: {new_user}")
        try:
            result = db.users.insert_one(new_user)
            logging.debug(f"Insert result: {result}")
            flash('Account created successfully', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            logging.error(f"Error inserting user: {str(e)}")
            flash('Error creating account', 'error')
    return render_template('register.html')

@app.template_filter('replace_usernames')
def replace_usernames(text):
    def replace_username(match):
        username = match.group(1)
        return f'<a href="{url_for("user_profile", username=username)}" class="text-blue-500 hover:underline">@{username}</a>'
    
    return re.sub(r'@(\w+)', replace_username, text)

@app.route('/profile/<username>')
@login_required
def user_profile(username):
    user = db.users.find_one({"username": username})
    if not user:
        return "User not found", 404
    posts = list(db.posts.find({"user_id": user['_id']}))
    followers_count = len(user.get('followers', []))
    following_count = len(user.get('following', []))
    posts_count = len(posts)
    
    return render_template(
        'profile.html',
        user=user,
        posts=posts,
        followers_count=followers_count,
        following_count=following_count,
        posts_count=posts_count
    )

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        db.users.update_one(
            {"_id": ObjectId(current_user.id)},
            {"$set": {"bio": request.form['bio']}}
        )
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                db.users.update_one(
                    {"_id": ObjectId(current_user.id)},
                    {"$set": {"profile_picture": filename}}
                )
        flash('Profile updated successfully')
        return redirect(url_for('user_profile', username=current_user.username))
    return render_template('edit_profile.html')

@app.route('/follow/<username>')
@login_required
def follow(username):
    user = db.users.find_one({"username": username})
    if user is None:
        flash('User not found.')
        return redirect(url_for('index'))
    if user['_id'] == ObjectId(current_user.id):
        flash('You cannot follow yourself!')
        return redirect(url_for('user_profile', username=username))
    current_user.follow(User(user))
    flash(f'You are now following {username}!')
    return redirect(url_for('user_profile', username=username))

@app.route('/unfollow/<username>')
@login_required
def unfollow(username):
    user = db.users.find_one({"username": username})
    if user is None:
        flash('User not found.')
        return redirect(url_for('index'))
    if user['_id'] == ObjectId(current_user.id):
        flash('You cannot unfollow yourself!')
        return redirect(url_for('user_profile', username=username))
    current_user.unfollow(User(user))
    flash(f'You have unfollowed {username}.')
    return redirect(url_for('user_profile', username=username))

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

@app.route('/post', methods=['POST'])
@login_required
def post():
    user_input = request.form.get('content', '').strip()
    if not user_input:
        return jsonify({'error': 'Post content cannot be empty!'}), 400

    prompt = f"""
    Analyze the following text for any violations of community guidelines. 
    If violations are found, provide a friendly explanation and suggest 3 alternative wordings.
    Make the suggestions fun and engaging.
    Text to analyze: "{user_input}"
    
    Respond in the following JSON format:
    {{
        "violates_guidelines": boolean,
        "explanation": "string",
        "suggestions": ["string"]
    }}
    """
    try:
        response = model.generate_content(prompt)
        logger.debug(f"Gemini response text: {response.text}")
        
        json_match = re.search(r'\{.*\}', response.text, re.DOTALL)
        if json_match:
            response_json = json_match.group(0)
            try:
                response_data = json.loads(response_json)
            except json.JSONDecodeError as e:
                logger.error(f"JSONDecodeError: {str(e)} - Response: {response_json}")
                return jsonify({'error': 'An error occurred while processing your post. Please try again.'}), 500
        else:
            raise ValueError("No valid JSON found in the response")
        
        logger.debug(f"Parsed response data: {response_data}")

        if response_data.get('violates_guidelines', False):
            return jsonify({
                'violates_guidelines': True,
                'explanation': response_data.get('explanation', 'No explanation provided.'),
                'suggestions': response_data.get('suggestions', [])
            }), 200
        
        new_post = {
            "content": user_input,
            "user_id": current_user.id,
            "timestamp": datetime.utcnow()
        }
        
        if 'media' in request.files:
            file = request.files['media']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                new_post["media_url"] = filename
        
        db.posts.insert_one(new_post)
        
        return jsonify({'success': True, 'message': 'Your post has been created!'}), 200

    except Exception as e:
        logger.error(f"Error processing or saving post: {str(e)}", exc_info=True)
        return jsonify({'error': 'An error occurred while processing your post. Please try again.'}), 500
    
    
@app.route('/submit_post', methods=['POST'])
@login_required
def submit_post():
    content = request.form.get('content', '').strip()
    if not content:
        return jsonify({'error': 'Post content cannot be empty!'}), 400

    # Use Gemini model to check for community guideline violations
    prompt = f"""
    Analyze the following text for any violations of community guidelines. 
    If violations are found, provide a friendly explanation and suggest 3 alternative wordings.
    Make the suggestions fun and engaging.
    Text to analyze: "{content}"
    
    Respond in the following JSON format:
    {{
        "violates_guidelines": boolean,
        "explanation": "string",
        "suggestions": ["string"]
    }}
    """
    try:
        response = model.generate_content(prompt)
        logger.debug(f"Gemini response text: {response.text}")
        
        # Extract JSON from the response
        json_match = re.search(r'\{.*\}', response.text, re.DOTALL)
        if json_match:
            response_data = json.loads(json_match.group(0))
        else:
            raise ValueError("No valid JSON found in the response")
        
        logger.debug(f"Parsed response data: {response_data}")

        if response_data.get('violates_guidelines', False):
            return jsonify({
                'violates_guidelines': True,
                'explanation': response_data.get('explanation', 'No explanation provided.'),
                'suggestions': response_data.get('suggestions', [])
            }), 200
        
        # If no violations, create the post
        new_post = {
            'content': content,
            'user_id': current_user.get_id(),
            'timestamp': datetime.utcnow()
        }
        
        if 'media' in request.files:
            file = request.files['media']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                new_post['media_url'] = filename
        
        db.posts.insert_one(new_post)
        
        return jsonify({'success': True, 'message': 'Your post has been created!'}), 200

    except Exception as e:
        logger.error(f"Error processing or saving post: {str(e)}", exc_info=True)
        return jsonify({'error': 'An error occurred while processing your post. Please try again.'}), 500

@app.route('/like/<post_id>', methods=['POST'])
@login_required
def like_post(post_id):
    post = db.posts.find_one({"_id": ObjectId(post_id)})
    if not post:
        return jsonify({'error': 'Post not found'}), 404
    
    user_id = current_user.get_id()
    if user_id not in post.get('likes', []):
        db.posts.update_one({"_id": ObjectId(post_id)}, {"$addToSet": {"likes": user_id}})
    else:
        db.posts.update_one({"_id": ObjectId(post_id)}, {"$pull": {"likes": user_id}})
    
    updated_post = db.posts.find_one({"_id": ObjectId(post_id)})
    return jsonify({'likes_count': len(updated_post.get('likes', [])), 'is_liked': user_id in updated_post.get('likes', [])})

@app.route('/comment/<post_id>', methods=['POST'])
@login_required
def add_comment(post_id):
    post = db.posts.find_one({"_id": ObjectId(post_id)})
    if not post:
        return jsonify({'error': 'Post not found'}), 404
    
    content = request.json.get('content')
    if content:
        comment = {
            'content': content,
            'author_id': current_user.get_id(),
            'timestamp': datetime.utcnow()
        }
        db.posts.update_one({"_id": ObjectId(post_id)}, {"$push": {"comments": comment}})
        
        return jsonify({
            'id': str(comment['_id']),
            'content': comment['content'],
            'author': current_user.username,
            'timestamp': comment['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
        }), 201
    return jsonify({'error': 'Comment content is required'}), 400

@app.route('/comment/<comment_id>', methods=['DELETE'])
@login_required
def delete_comment(comment_id):
    post = db.posts.find_one({"comments._id": ObjectId(comment_id)})
    if not post:
        return jsonify({'error': 'Comment not found'}), 404
    
    comment = next((c for c in post['comments'] if str(c['_id']) == comment_id), None)
    if comment and comment['author_id'] != current_user.get_id():
        return jsonify({'error': 'Unauthorized'}), 403
    
    db.posts.update_one({"_id": post['_id']}, {"$pull": {"comments": {"_id": ObjectId(comment_id)}}})
    return jsonify({'message': 'Comment deleted successfully'}), 200

@app.route('/delete_post/<post_id>', methods=['DELETE'])
@login_required
def delete_post(post_id):
    post = db.posts.find_one({"_id": ObjectId(post_id)})
    if not post:
        return jsonify({'error': 'Post not found'}), 404
    
    if post['user_id'] != current_user.get_id():
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403
    
    db.posts.delete_one({"_id": ObjectId(post_id)})
    return jsonify({'status': 'success', 'message': 'Post deleted successfully'}), 200

@app.route('/conversations')
def conversations():
    return redirect(url_for('messages'))

@app.route('/messages/', defaults={'recipient_id': None})
@app.route('/messages/<recipient_id>')
@login_required
def messages(recipient_id):
    available_users = get_available_users()
    
    # Check if available_users is not empty and has the '_id' key
    if recipient_id is None and available_users:
        if isinstance(available_users, list) and isinstance(available_users[0], dict) and '_id' in available_users[0]:
            recipient_id = available_users[0]['_id']
        else:
            # Handle the case where '_id' is missing or available_users is not as expected
            recipient_id = None  # Or some default value
            # You might want to add a flash message or log the error

    recipient = db.users.find_one({"_id": ObjectId(recipient_id)}) if recipient_id else None
    messages = get_messages(current_user.get_id(), recipient_id) if recipient_id else []
    starters = suggest_conversation_starters(current_user.get_id(), recipient_id) if recipient_id else []
    
    return render_template('messages.html', 
                           messages=messages, 
                           starters=starters, 
                           recipient=recipient, 
                           available_users=available_users,
                           current_user=current_user)
@app.route('/api/conversation_starters/<other_user_id>')
@login_required
def api_conversation_starters(other_user_id):
    starters = suggest_conversation_starters(current_user.get_id(), other_user_id)
    return jsonify({'starters': starters})

@app.route('/send_message/<recipient_id>', methods=['POST'])
@login_required
def send_message_route(recipient_id):
    content = request.form['content']
    media = request.files.get('media')
    media_url = None
    ai_response_flag = request.form.get('ai_response', 'false').lower() == 'true'
    
    moderation_result = moderate_content(content)
    if moderation_result['violates_guidelines']:
        flash('Content violates guidelines: ' + moderation_result['explanation'])
        return redirect(url_for('messages', recipient_id=recipient_id))
    
    if media and allowed_file(media.filename):
        filename = secure_filename(media.filename)
        media_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        media.save(media_path)
        media_url = url_for('static', filename=f'uploads/{filename}')
    
    new_message, error = send_message_helper(current_user.get_id(), recipient_id, content, media_url)
    
    if error:
        flash('Error sending message: ' + error)
        return redirect(url_for('messages', recipient_id=recipient_id))
    
    message_data = {
        'id': str(new_message['_id']),
        'sender_id': current_user.get_id(),
        'recipient_id': recipient_id,
        'content': content,
        'media_url': media_url,
        'timestamp': new_message['timestamp'].isoformat()
    }
    
    socketio.emit('new_message', message_data, room=str(recipient_id))
    socketio.emit('new_message', message_data, room=str(current_user.get_id()))
    
    # Generate AI reply if the flag is set
    if ai_response_flag:
        ai_reply = generate_ai_reply(content)
        if ai_reply:
            ai_message, _ = send_message_helper(recipient_id, current_user.get_id(), ai_reply)
            ai_message_data = {
                'id': str(ai_message['_id']),
                'sender_id': recipient_id,
                'recipient_id': current_user.get_id(),
                'content': ai_reply,
                'timestamp': ai_message['timestamp'].isoformat()
            }
            socketio.emit('new_message', ai_message_data, room=str(current_user.get_id()))
    
    return redirect(url_for('messages', recipient_id=recipient_id))

def generate_ai_reply(content):
    prompt = f"""
    Given the following message, suggest a thoughtful and engaging reply:
    "{content}"
    Keep the reply concise and natural-sounding. Include appropriate emojis to make the message more engaging.
    Do not use asterisks or any other formatting. The reply should be ready to send as-is.
    """
    
    # Call the model's generate_content function synchronously
    response = model.generate_content(prompt)
    
    # Use the emojis library to add emojis to the response text
    return emojis.encode(response.text, language='alias')



@app.route('/generate_ai_reply/<recipient_id>', methods=['GET'])
@login_required
def api_generate_ai_reply(recipient_id):
    # Fetch the latest message content from the chat with the recipient
    last_message = db.messages.find_one(
        {"sender_id": current_user.id, "recipient_id": ObjectId(recipient_id)},
        sort=[("timestamp", pymongo.DESCENDING)]
    )
    
    if last_message:
        content = last_message['content']
        ai_reply = generate_ai_reply(content)
        
        # Send the AI reply to the chat
        new_message, error = send_message_helper(current_user.id, recipient_id, ai_reply)
        if error:
            return jsonify({'error': error}), 400
        
        message_data = {
            'id': str(new_message['_id']),
            'sender_id': current_user.id,
            'recipient_id': recipient_id,
            'content': ai_reply,
            'timestamp': new_message['timestamp'].isoformat()
        }
        
        # Broadcast the AI message to both users
        socketio.emit('new_message', message_data, room=str(recipient_id))
        socketio.emit('new_message', message_data, room=str(current_user.id))
        
        return jsonify({'reply': ai_reply}), 200
    else:
        return jsonify({'error': 'No previous message found to base AI reply on'}), 400

def send_message_helper(sender_id, recipient_id, content, media_url=None):
    try:
        if not content.strip():
            return None, "Message content cannot be empty."

        new_message = {
            'sender_id': sender_id,
            'recipient_id': ObjectId(recipient_id),
            'content': content,
            'media_url': media_url,
            'timestamp': datetime.utcnow()
        }

        db.messages.insert_one(new_message)
        return new_message, None

    except Exception as e:
        return None, f"An error occurred: {str(e)}"

def get_messages(current_user_id, recipient_id, page=1, per_page=20):
    messages = db.messages.find({
        "$or": [
            {"sender_id": current_user_id, "recipient_id": ObjectId(recipient_id)},
            {"sender_id": ObjectId(recipient_id), "recipient_id": current_user_id}
        ]
    }).sort("timestamp", pymongo.ASCENDING).skip((page-1) * per_page).limit(per_page)
    return list(messages)

@app.route('/delete_chat_history/<recipient_id>', methods=['POST'])
@login_required
def delete_chat_history(recipient_id):
    try:
        # Delete messages where the current user is either the sender or the recipient
        db.messages.delete_many({
            "$or": [
                {"sender_id": current_user.id, "recipient_id": ObjectId(recipient_id)},
                {"sender_id": ObjectId(recipient_id), "recipient_id": current_user.id}
            ]
        })

        return jsonify({"success": True, "message": "Chat history deleted successfully"}), 200
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

def get_available_users():
    users = db.users.find({"_id": {"$ne": current_user.id}})
    return [{'id': str(user['_id']), 'username': user['username'], 'profile_picture': user.get('profile_picture', 'default.jpg')} for user in users]


def suggest_conversation_starters(user_id, other_user_id):
    user = db.users.find_one({"_id": ObjectId(user_id)})
    other_user = db.users.find_one({"_id": ObjectId(other_user_id)})
    
    # Check if the 'bio' key exists for both users, and provide a default value if not
    user_bio = user.get('bio', 'No bio available 😔')
    other_user_bio = other_user.get('bio', 'No bio available 😔')
    
    prompt = f"""
        Suggest 3 fun and engaging conversation starters for two users based on their profiles. 
        Make sure to include emojis to make the conversation starters more lively and enjoyable!
        
        User 1: {user_bio}
        User 2: {other_user_bio}
        
        Provide creative and relevant conversation starters that could help these users connect with a smile. 
        """

    response = model.generate_content(prompt)
    return response.text.split('\n')
@app.route('/notifications')
@login_required
def notifications():
    # Retrieve notifications for the current user, sorted by timestamp in descending order
    notifications = list(db.notifications.find({"user_id": ObjectId(current_user.id)}).sort("timestamp", DESCENDING))
    
    # Optionally, you can mark notifications as read here if you want to update their status upon viewing
    # For example:
    db.notifications.update_many({"user_id": ObjectId(current_user.id), "read": False}, {"$set": {"read": True}})
    
    return render_template('notifications.html', notifications=notifications)

def create_notification(user_id, content):
    new_notification = {
        'user_id': user_id,
        'content': content,
        'timestamp': datetime.utcnow()
    }
    db.notifications.insert_one(new_notification)
    socketio.emit('new_notification', {'user_id': user_id, 'content': content}, room=str(user_id))

@socketio.on('typing')
def handle_typing(data):
    recipient_id = data['recipient_id']
    socketio.emit('typing', {'sender_id': current_user.id}, room=str(recipient_id))

@socketio.on('stop_typing')
def handle_stop_typing(data):
    recipient_id = data['recipient_id']
    socketio.emit('stop_typing', {'sender_id': current_user.id}, room=str(recipient_id))

@socketio.on('message_read')
def handle_message_read(data):
    message_id = data['message_id']
    message = db.messages.find_one({"_id": ObjectId(message_id)})
    if message:
        db.messages.update_one({"_id": ObjectId(message_id)}, {"$set": {"read": True}})
        socketio.emit('message_status_update', {'message_id': message_id, 'read': True}, room=str(message['sender_id']))

@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        join_room(str(current_user.id))

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        leave_room(str(current_user.id))

@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(days=30)
    
def moderate_content(content):
    prompt = f"""
    Analyze the following content for appropriateness on a social media platform. Please take into account common community guidelines which may include but are not limited to: harassment, hate speech, violence, explicit content, misinformation, and spam.

    Content to analyze:
    "{content}"

    Please provide the following in your response:
    1. **Violates Guidelines**: Determine if the content violates any common social media community guidelines. Respond with `true` if it violates, otherwise `false`.
    2. **Explanation**: Provide a brief explanation for your determination. Mention which specific guideline(s) are potentially violated or why the content is considered appropriate.
    3. **Sentiment Analysis**: Analyze the sentiment of the content and classify it as `positive`, `neutral`, or `negative`. Provide reasoning for the sentiment classification.
    4. **Suggestions for Improvement**: If the content is borderline inappropriate or has potential issues, suggest specific ways to improve it to make it more suitable for a social media platform. 

    Format your response as a JSON object with the following keys:
    - `"violates_guidelines"`: (boolean) `true` or `false` indicating if the content violates guidelines.
    - `"explanation"`: (string) A brief explanation of why the content does or does not violate guidelines.
    - `"sentiment"`: (string) The sentiment analysis result, which can be `positive`, `neutral`, or `negative`.
    - `"suggestions"`: (array of strings) Suggestions for improving the content if needed.

    Example of a JSON response:
    {{
        "violates_guidelines": true,
        "explanation": "The content contains explicit language which violates our community guidelines on harassment.",
        "sentiment": "negative",
        "suggestions": ["Remove explicit language", "Rephrase the content to be more respectful."]
    }}
    """

    try:
        response = model.generate_content(prompt)
        response_text = getattr(response, 'text', '').strip()

        # Log the response text for debugging
        print(f"Response text: {response_text}")

        if not response_text:
            raise ValueError("Received an empty response from the model")

        # Try to parse the JSON response
        try:
            moderation_result = json.loads(response_text)
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON: {e}")
            print(f"Response text: {response_text}")
            
            # Attempt to extract JSON from the response if it's not properly formatted
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if json_match:
                try:
                    moderation_result = json.loads(json_match.group())
                except json.JSONDecodeError:
                    raise ValueError("Unable to extract valid JSON from the model's response")
            else:
                raise ValueError("No JSON-like structure found in the model's response")

        # Validate the structure of the moderation result
        required_keys = ['violates_guidelines', 'explanation', 'sentiment', 'suggestions']
        if not all(key in moderation_result for key in required_keys):
            raise ValueError("Moderation result is missing required keys")

        # Check for vulgar language
        if moderation_result.get("violates_guidelines") and "explicit" in moderation_result.get("explanation", "").lower():
            moderation_result["suggestions"].append("Please avoid using vulgar language.")

        return moderation_result

    except Exception as e:
        print(f"Error in moderate_content: {str(e)}")
        # Return a default response in case of any error
        return {
            "violates_guidelines": False,
            "explanation": "Unable to analyze content due to an error.",
            "sentiment": "neutral",
            "suggestions": ["Please try again later."]
        }

if __name__ == '__main__':
    socketio.run(app, debug=True)
