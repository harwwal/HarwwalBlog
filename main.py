from functools import wraps
from flask import abort
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from wtforms import *
from forms import *
from flask_gravatar import Gravatar
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)


#CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

#Flakes Login Setup
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)



#CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)

    # This will act like a List of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.
    posts = db.relationship("BlogPost", back_populates="author")
    comments = db.relationship("Comment", back_populates="user_comment")




class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # Create reference to the User object, the "posts" refers to the posts protperty in the User class.
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
# Create Foreign Key, "users.id" the users refers to the tablename of User
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    post_comments = db.relationship("Comment", back_populates="parent_post")


class Comment(db.Model):
    __tablename__ = "comment"
    id = db.Column(db.Integer, primary_key=True)
    comment_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    user_comment = db.relationship("User", back_populates="comments")
    parent_post = db.relationship("BlogPost", back_populates="post_comments")
    text = db.Column(db.Text, nullable=False)
    post_id = db.Column(db.String(250), db.ForeignKey("blog_posts.title"))



db.create_all()


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        #Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/', methods=['GET', 'POST'])
@login_required
def get_all_posts():
    posts = BlogPost.query.all()

    print(current_user.get_id())
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated,
                           the_id=current_user.get_id())


@app.route('/register', methods=['GET', 'POST'])
def register():
    reg_form = RegisterForm()
    all_user = db.session.query(User).all()
    if request.method == 'GET':
        return render_template("register.html", form=reg_form)
    else:
        if reg_form.validate_on_submit():
            the_hash = generate_password_hash(reg_form.password.data, method='pbkdf2:sha256', salt_length=8)
            the_email = reg_form.email.data
            for user in all_user:
                if the_email == user.email:
                    flash('The email you entered is Already registered, Login instead.')
                    return redirect(url_for('login'))
                else:
                    this_user = User(
                        name=reg_form.name.data,
                        email=the_email,
                        password=the_hash)
                    db.session.add(this_user)
                    db.session.commit()
                    login_user(this_user)
                    return redirect(url_for("get_all_posts"))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        email = form.email.data
        password = form.password.data
        remember = True if request.form.get('remember') else False
        user = User.query.filter_by(email=email).first()
        # pass_check = check_password_hash(user.password, password)
        if user and check_password_hash(user.password, password):
            login_user(user, remember=remember)
            return redirect(url_for("get_all_posts"))
        elif not user:
            flash('Please check your login details and try again.')
            return redirect(url_for('login', form=form))
        elif not check_password_hash(user.password, password):
            flash('Password Incorrect.')
            return redirect(url_for('login', form=form))
    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'] )
def show_post(post_id):
    comment_form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    comments = Comment.query.all()
    if request.method == 'POST':
        new_comment = Comment(text=comment_form.body.data)
        db.session.add(new_comment)
        db.session.commit()
        return render_template("post.html", post=requested_post, form=comment_form, comments=comments)
    else:
        return render_template("post.html", post=requested_post, form=comment_form, comments=comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods= ['GET', 'POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
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
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
