import os, re, secrets
from datetime import datetime
from functools import wraps

from flask import Flask, render_template, redirect, url_for, flash, abort, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                         login_required, current_user)
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo, Regexp, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
IS_PROD = os.environ.get("FLASK_ENV") == "production"

db_url = os.environ.get("DATABASE_URL", "sqlite:///app.db")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SQLALCHEMY_DATABASE_URI=db_url,
    SESSION_COOKIE_HTTPONLY=True,      # JS อ่าน cookie ไม่ได้ (กัน XSS ขโมย session)
    SESSION_COOKIE_SAMESITE="Lax",     # ลด CSRF
    SESSION_COOKIE_SECURE=IS_PROD,     # ส่งเฉพาะ HTTPS
    MAX_CONTENT_LENGTH=64 * 1024,      # จำกัดขนาด request
)

db = SQLAlchemy(app)
csrf = CSRFProtect(app)                # CSRF token ทุกฟอร์ม POST
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per hour"])
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "กรุณาเข้าสู่ระบบก่อน"

DUMMY_HASH = generate_password_hash("dummy-password")


# ---------- Models ----------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(10), nullable=False, default="user")  # user | admin
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    posts = db.relationship("Post", backref="owner", cascade="all, delete-orphan")
    comments = db.relationship("Comment", backref="author", cascade="all, delete-orphan")

    @property
    def is_admin(self):
        return self.role == "admin"


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    content = db.Column(db.Text, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    comments = db.relationship("Comment", backref="post", cascade="all, delete-orphan",
                               order_by="Comment.created_at")


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(500), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("post.id"), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


@login_manager.user_loader
def load_user(uid):
    return db.session.get(User, int(uid))


# ---------- Forms (validate ฝั่งเซิร์ฟเวอร์) ----------
class RegisterForm(FlaskForm):
    username = StringField("ชื่อผู้ใช้", validators=[
        DataRequired(), Regexp(r"^[A-Za-z0-9_]{3,30}$", message="3-30 ตัว: a-z 0-9 _ เท่านั้น")])
    password = PasswordField("รหัสผ่าน", validators=[
        DataRequired(), Length(min=8, max=128, message="รหัสผ่านต้องยาว 8-128 ตัวอักษร")])
    confirm = PasswordField("ยืนยันรหัสผ่าน", validators=[
        DataRequired(), EqualTo("password", message="รหัสผ่านไม่ตรงกัน")])

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError("ชื่อผู้ใช้นี้ถูกใช้แล้ว")


class LoginForm(FlaskForm):
    username = StringField("ชื่อผู้ใช้", validators=[DataRequired(), Length(max=30)])
    password = PasswordField("รหัสผ่าน", validators=[DataRequired(), Length(max=128)])


class PostForm(FlaskForm):  # ฟอร์มที่ 1
    title = StringField("หัวข้อ", validators=[DataRequired(), Length(max=120)])
    content = TextAreaField("เนื้อหา", validators=[DataRequired(), Length(max=5000)])


class CommentForm(FlaskForm):  # ฟอร์มที่ 2
    body = StringField("ความคิดเห็น", validators=[DataRequired(), Length(max=500)])


# ---------- Authorization ----------
def admin_required(f):
    @wraps(f)
    @login_required
    def wrapper(*a, **kw):
        if not current_user.is_admin:
            abort(403)
        return f(*a, **kw)
    return wrapper


def owned_post_or_403(post_id):
    post = db.get_or_404(Post, post_id)
    if post.owner_id != current_user.id:      # ตรวจความเป็นเจ้าของทุกครั้ง (กัน IDOR)
        abort(403)
    return post


# ---------- Auth routes ----------
@app.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per hour", methods=["POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(username=form.username.data,
                    password_hash=generate_password_hash(form.password.data),  # salted hash
                    role="user")  # สมัครเองได้เป็น user เท่านั้น
        db.session.add(user)
        db.session.commit()
        flash("สมัครสมาชิกสำเร็จ กรุณาเข้าสู่ระบบ", "ok")
        return redirect(url_for("login"))
    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])  # กัน brute force
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        ok = check_password_hash(user.password_hash if user else DUMMY_HASH, form.password.data)
        if user and ok:
            login_user(user)
            return redirect(url_for("index"))
        flash("ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง", "err")  # ข้อความเดียว ไม่บอกว่าผิดช่องไหน
    return render_template("login.html", form=form)


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


# ---------- Posts CRUD (มีเจ้าของ) ----------
@app.route("/")
def index():
    posts = Post.query.order_by(Post.created_at.desc()).all()
    return render_template("index.html", posts=posts, delete_form=FlaskForm())


@app.route("/post/new", methods=["GET", "POST"])
@login_required
def post_new():
    form = PostForm()
    if form.validate_on_submit():
        p = Post(title=form.title.data, content=form.content.data, owner_id=current_user.id)
        db.session.add(p)
        db.session.commit()
        flash("สร้างโพสต์แล้ว", "ok")
        return redirect(url_for("post_detail", post_id=p.id))
    return render_template("post_form.html", form=form, heading="สร้างโพสต์ใหม่")


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def post_detail(post_id):
    post = db.get_or_404(Post, post_id)
    form = CommentForm()
    if request.method == "POST":
        if not current_user.is_authenticated:
            abort(401)
        if form.validate_on_submit():
            db.session.add(Comment(body=form.body.data, post_id=post.id, author_id=current_user.id))
            db.session.commit()
            return redirect(url_for("post_detail", post_id=post.id))
    return render_template("post_detail.html", post=post, form=form, delete_form=FlaskForm())


@app.route("/post/<int:post_id>/edit", methods=["GET", "POST"])
@login_required
def post_edit(post_id):
    post = owned_post_or_403(post_id)
    form = PostForm(obj=post)
    if form.validate_on_submit():
        post.title, post.content = form.title.data, form.content.data
        db.session.commit()
        flash("แก้ไขโพสต์แล้ว", "ok")
        return redirect(url_for("post_detail", post_id=post.id))
    return render_template("post_form.html", form=form, heading="แก้ไขโพสต์")


@app.route("/post/<int:post_id>/delete", methods=["POST"])
@login_required
def post_delete(post_id):
    post = db.get_or_404(Post, post_id)
    if post.owner_id != current_user.id and not current_user.is_admin:  # admin ลบเพื่อ moderate ได้
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash("ลบโพสต์แล้ว", "ok")
    return redirect(url_for("index"))


@app.route("/comment/<int:cid>/delete", methods=["POST"])
@login_required
def comment_delete(cid):
    c = db.get_or_404(Comment, cid)
    if c.author_id != current_user.id and not current_user.is_admin:
        abort(403)
    pid = c.post_id
    db.session.delete(c)
    db.session.commit()
    return redirect(url_for("post_detail", post_id=pid))


# ---------- Admin ----------
@app.route("/admin")
@admin_required
def admin():
    users = User.query.order_by(User.id).all()
    return render_template("admin.html", users=users, form=FlaskForm(),
                           n_posts=Post.query.count(), n_comments=Comment.query.count())


@app.route("/admin/users/<int:uid>/role", methods=["POST"])
@admin_required
def admin_role(uid):
    u = db.get_or_404(User, uid)
    if u.id == current_user.id:
        flash("ไม่สามารถเปลี่ยนบทบาทของตัวเองได้", "err")
    else:
        u.role = "admin" if u.role == "user" else "user"
        db.session.commit()
    return redirect(url_for("admin"))


@app.route("/admin/users/<int:uid>/delete", methods=["POST"])
@admin_required
def admin_delete_user(uid):
    u = db.get_or_404(User, uid)
    if u.id == current_user.id:
        flash("ไม่สามารถลบตัวเองได้", "err")
    else:
        db.session.delete(u)
        db.session.commit()
    return redirect(url_for("admin"))


# ---------- Errors & security headers ----------
@app.errorhandler(401)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(429)
def err(e):
    return render_template("error.html", code=e.code, msg=e.name), e.code


@app.after_request
def headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; script-src 'none'; "
        "frame-ancestors 'none'; form-action 'self'; base-uri 'self'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    if IS_PROD:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    return resp


# ---------- Init & seed admin ----------
with app.app_context():
    db.create_all()
    au, ap = os.environ.get("ADMIN_USERNAME"), os.environ.get("ADMIN_PASSWORD")
    if au and ap and not User.query.filter_by(username=au).first():
        db.session.add(User(username=au, password_hash=generate_password_hash(ap), role="admin"))
        db.session.commit()

if __name__ == "__main__":
    app.run(debug=False)
