from flask import Blueprint, abort, jsonify, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from pymongo import MongoClient
from bson.objectid import ObjectId
from datetime import datetime
import os
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

profile = Blueprint('prof', __name__)

# Configure Gemini AI
genai.configure(api_key=os.getenv('GEMINI_API_KEY'))
model = genai.GenerativeModel('gemini-pro')

# MongoDB client setup
client = MongoClient(os.getenv('MONGO_URI'))
db = client['your_database_name']
users_collection = db['users']
posts_collection = db['posts']
follows_collection = db['follows']

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@profile.route('/profile/<username>')
@login_required
def user_profile(username):
    user = db.users.find_one({'username': username})
    if not user:
        abort(404)
    
    posts = db.posts.find({'author_id': user['_id']})
    posts_count = db.posts.count_documents({'author_id': user['_id']})
    followers_count = db.users.count_documents({'followed': user['_id']})
    following_count = len(user.get('followed', []))
    
    return render_template(
        'profile.html', 
        user=user, 
        posts=posts, 
        posts_count=posts_count,
        followers_count=followers_count,
        following_count=following_count
    )


@profile.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        bio = request.form.get('bio')
        location = request.form.get('location')

        update_data = {}
        if username:
            update_data['username'] = username
        if email:
            update_data['email'] = email
        if bio:
            update_data['bio'] = bio
        if location:
            update_data['location'] = location

        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join('static/uploads', filename))
                update_data['profile_picture'] = filename

        users_collection.update_one({'_id': current_user.id}, {'$set': update_data})
        flash('Your profile has been updated.', 'success')
        return redirect(url_for('prof.user_profile', username=current_user.username))

    return render_template('edit_profile.html', user=current_user)

@profile.route('/follow/<username>', methods=['POST'])
@login_required
def follow(username):
    user = users_collection.find_one({'username': username})
    if not user:
        flash(f'User {username} not found.', 'error')
        return redirect(url_for('prof.user_profile', username=current_user.username))

    follow_data = {'follower_id': current_user.id, 'followed_id': user['_id']}
    if not follows_collection.find_one(follow_data):
        follows_collection.insert_one(follow_data)
        flash(f'You are now following {username}!', 'success')
    else:
        flash(f'You are already following {username}.', 'info')

    return redirect(url_for('prof.user_profile', username=username))

@profile.route('/unfollow/<username>', methods=['POST'])
@login_required
def unfollow(username):
    user = users_collection.find_one({'username': username})
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('index'))
    if user['_id'] == current_user.id:
        flash('You cannot unfollow yourself!', 'error')
        return redirect(url_for('prof.user_profile', username=username))

    follows_collection.delete_one({'follower_id': current_user.id, 'followed_id': user['_id']})
    flash(f'You have unfollowed {username}.', 'success')
    return redirect(url_for('prof.user_profile', username=username))

@profile.route('/post/<post_id>/like', methods=['POST'])
@login_required
def like_post(post_id):
    post = posts_collection.find_one({'_id': ObjectId(post_id)})
    if not post:
        return "Post not found", 404
    if current_user.id not in post.get('likes', []):
        posts_collection.update_one({'_id': ObjectId(post_id)}, {'$addToSet': {'likes': current_user.id}})
    return redirect(request.referrer)

@profile.route('/post/<post_id>/unlike', methods=['POST'])
@login_required
def unlike_post(post_id):
    post = posts_collection.find_one({'_id': ObjectId(post_id)})
    if not post:
        return "Post not found", 404
    if current_user.id in post.get('likes', []):
        posts_collection.update_one({'_id': ObjectId(post_id)}, {'$pull': {'likes': current_user.id}})
    return redirect(request.referrer)
