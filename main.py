from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from sqlalchemy.ext.declarative import declarative_base
import hashlib
import bleach
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "sqlite:///blog.db")
ckeditor = CKEditor(app)
Bootstrap(app)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
# app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///blog.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
Base = declarative_base()
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False,
                    base_url=None)


# Create admin-only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #If id is not 1 then return abort with 403 error
        if int(current_user.get_id()) != 1:
            return abort(403)
        #Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function


def owner_of_post(post):
    if post.author == current_user:
        return True
    return False


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def strip_invalid_html(content):
    allowed_tags = ['a', 'abbr', 'acronym', 'address', 'b', 'br', 'div', 'dl', 'dt',
                    'em', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'hr', 'i', 'img',
                    'li', 'ol', 'p', 'pre', 'q', 's', 'small', 'strike',
                    'span', 'sub', 'sup', 'table', 'tbody', 'td', 'tfoot', 'th',
                    'thead', 'tr', 'tt', 'u', 'ul']

    allowed_attrs = {
        'a': ['href', 'target', 'title'],
        'img': ['src', 'alt', 'width', 'height'],
    }

    cleaned = bleach.clean(content,
                           tags=allowed_tags,
                           attributes=allowed_attrs,
                           strip=True)

    return cleaned


# CONFIGURE TABLES
class User(UserMixin, db.Model, Base):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="author")


class BlogPost(db.Model, Base):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = relationship("User", back_populates="posts")
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    title = db.Column(db.String(250), nullable=False, unique=True)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")


class Comment(db.Model, Base):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author = relationship("User", back_populates="comments")
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    text = db.Column(db.Text, nullable=False)
# db.create_all()


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    c_date = date.today().strftime("%Y")
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated, c_date=c_date)


@app.route('/register', methods=["POST", "GET"])
def register():
    form = RegisterForm()
    c_date = date.today().strftime("%Y")
    if form.validate_on_submit():
        new_user = User()
        if User.query.filter_by(email=form.email.data).first():
            flash("An account has already been created under this email, please login or use a different email.")
            return redirect("login")
        new_user.email = form.email.data
        new_user.name = form.name.data
        new_user.password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect("/")
    return render_template("register.html", form=form, logged_in=current_user.is_authenticated, c_date=c_date)


@app.route('/login', methods=["POST", "GET"])
def login():
    form = LoginForm()
    c_date = date.today().strftime("%Y")
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        # Email doesn't exist
        if not user:
            flash("That email is not associated with an account, please try again.")
            return redirect("login")
        # Password incorrect
        elif not check_password_hash(user.password, password):
            flash('That password does not match the email, please try again.')
            return redirect("login")
        # Email exists and password correct
        else:
            login_user(user)
            return redirect("/")
    return render_template("login.html", form=form, logged_in=current_user.is_authenticated, c_date=c_date)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect("/")


@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    form = CommentForm()
    c_date = date.today().strftime("%Y")
    requested_post = BlogPost.query.get(post_id)
    comments = Comment.query.filter_by(post_id=post_id).all()
    logged_in = current_user.is_authenticated
    md5_email_hash = hashlib.md5()
    md5_email_hash.update(b'Hello World')
    if form.validate_on_submit():
        if not logged_in:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))
        new_comment = Comment()
        new_comment.text = form.body.data
        new_comment.author = current_user
        new_comment.parent_post = BlogPost.query.first()
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("show_post", post_id=post_id))
    return render_template("post.html", form=form, post=requested_post, logged_in=logged_in, comments=comments,
                           hash=str(md5_email_hash.digest()), c_date=c_date)


@app.route("/about")
def about():
    c_date = date.today().strftime("%Y")
    return render_template("about.html", logged_in=current_user.is_authenticated, c_date=c_date)


@app.route("/contact")
def contact():
    c_date = date.today().strftime("%Y")
    return render_template("contact.html", logged_in=current_user.is_authenticated, c_date=c_date)


@app.route("/new-post", methods=["POST", "GET"])
@login_required
def add_new_post():
    form = CreatePostForm()
    c_date = date.today().strftime("%Y")
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=strip_invalid_html(form.body.data),
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user,
                           logged_in=current_user.is_authenticated, c_date=c_date)


@app.route("/edit-post/<int:post_id>", methods=["POST", "GET"])
@login_required
def edit_post(post_id):
    c_date = date.today().strftime("%Y")
    post = BlogPost.query.get(post_id)
    if owner_of_post(post):
        edit_form = CreatePostForm(
            title=post.title,
            subtitle=post.subtitle,
            img_url=post.img_url,
            author=post.author,
            body=post.body
        )
        if edit_form.validate_on_submit():
            post.title = edit_form.title.data
            post.subtitle = edit_form.subtitle.data
            post.img_url = edit_form.img_url.data
            post.body = strip_invalid_html(edit_form.body.data)
            db.session.commit()
            return redirect(url_for("show_post", post_id=post.id))

        return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated, c_date=c_date)
    else:
        return abort(403)


@app.route("/delete/<int:post_id>")
@login_required
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    if owner_of_post(post_to_delete):
        db.session.delete(post_to_delete)
        db.session.commit()
    else:
        return abort(403)
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run()
