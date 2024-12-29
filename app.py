import os
from dotenv import load_dotenv
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, IntegerField, DateField
from wtforms.validators import DataRequired, Length, Optional, NumberRange
from flask_migrate import Migrate
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import WebApplicationClient
import hashlib

# Load environment variables
load_dotenv()
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # 開発環境でのみ使用

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', os.urandom(24))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET')

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'index'

# OAuth2 configuration
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
client = WebApplicationClient(app.config['GOOGLE_CLIENT_ID'])

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    google_id = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    user_type = db.Column(db.String(20), nullable=False)  # 'engineer' or 'client'
    profile = db.Column(db.Text)
    hourly_rate = db.Column(db.Integer)
    picture = db.Column(db.String(200))  # Google profile picture URL
    created_at = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

    __table_args__ = (
        db.UniqueConstraint('google_id', 'user_type', name='unique_google_id_user_type'),
    )

    @property
    def username(self):
        return self.name

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    budget_min = db.Column(db.Integer)
    budget_max = db.Column(db.Integer)
    deadline = db.Column(db.Date)
    expires_at = db.Column(db.Date)
    created_at = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

    client = db.relationship('User', backref=db.backref('projects', lazy=True))

class Proposal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    engineer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    url = db.Column(db.String(200))
    expires_at = db.Column(db.Date)
    created_at = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

    project = db.relationship('Project', backref=db.backref('proposals', lazy=True))
    engineer = db.relationship('User', backref=db.backref('proposals', lazy=True))

# Forms
class ProjectForm(FlaskForm):
    title = StringField('案件タイトル', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('要件定義', validators=[DataRequired()])
    budget_min = IntegerField('最小金額', validators=[Optional(), NumberRange(min=0)])
    budget_max = IntegerField('最大金額', validators=[Optional(), NumberRange(min=0)])
    deadline = DateField('納期', validators=[DataRequired()])
    expires_at = DateField('募集期限', validators=[DataRequired()])

class ProposalForm(FlaskForm):
    content = TextAreaField('提案内容', validators=[DataRequired(), Length(max=2000)])
    url = StringField('ポートフォリオURL', validators=[Optional(), Length(max=200)])
    expires_at = DateField('提案の有効期限', validators=[DataRequired()])

class ProfileForm(FlaskForm):
    name = StringField('名前', validators=[DataRequired(), Length(max=100)])
    profile = TextAreaField('プロフィール', validators=[Optional(), Length(max=1000)])
    hourly_rate = IntegerField('希望単価', validators=[Optional(), NumberRange(min=0, max=100000)])

# Login manager
@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

@login_manager.unauthorized_handler
def unauthorized():
    return redirect(url_for('index'))

# Template filters
@app.template_filter('hash')
def hash_filter(value):
    return hashlib.md5(value.encode('utf-8')).hexdigest()

@app.template_filter('nl2br')
def nl2br_filter(s):
    return s.replace('\n', '<br>') if s else ''

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login/<user_type>')
def login(user_type):
    if user_type not in ['client', 'engineer']:
        return redirect(url_for('index'))

    session['user_type'] = user_type
    authorization_endpoint = "https://accounts.google.com/o/oauth2/v2/auth"
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=url_for('callback', _external=True),
        scope=['openid', 'email', 'profile'],
        state=user_type
    )
    return redirect(request_uri)

@app.route('/auth/google/callback')
def callback():
    code = request.args.get("code")
    user_type = request.args.get("state")
    
    if not code:
        return redirect(url_for('index'))

    try:
        token_endpoint = "https://oauth2.googleapis.com/token"
        token_url, headers, body = client.prepare_token_request(
            token_endpoint,
            authorization_response=request.url,
            redirect_url=request.base_url,
            code=code
        )
        token_response = OAuth2Session(
            app.config['GOOGLE_CLIENT_ID'],
            redirect_uri=request.base_url
        ).fetch_token(
            token_url,
            client_secret=app.config['GOOGLE_CLIENT_SECRET'],
            authorization_response=request.url,
        )

        oauth = OAuth2Session(app.config['GOOGLE_CLIENT_ID'], token=token_response)
        userinfo = oauth.get("https://openidconnect.googleapis.com/v1/userinfo").json()

        if not userinfo.get("email_verified"):
            return redirect(url_for('index'))

        google_id = userinfo["sub"]
        email = userinfo["email"]
        name = userinfo["name"]
        picture = userinfo.get("picture")
        user_type = user_type or session.get('user_type', 'engineer')

        existing_user = User.query.filter_by(google_id=google_id, user_type=user_type).first()
        if existing_user:
            existing_user.picture = picture
            db.session.commit()
            login_user(existing_user)
            return redirect(url_for('dashboard'))

        user = User(
            google_id=google_id,
            email=email,
            name=name,
            user_type=user_type,
            picture=picture
        )
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('dashboard'))

    except Exception as e:
        print(f"Error during authentication: {str(e)}")
        return redirect(url_for('index'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    template = 'dashboard_engineer.html' if current_user.user_type == 'engineer' else 'dashboard_client.html'
    return render_template(template)

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = ProfileForm(obj=current_user)
    
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.profile = form.profile.data
        if current_user.user_type == 'engineer' and form.hourly_rate.data:
            current_user.hourly_rate = form.hourly_rate.data
        
        try:
            db.session.commit()
            return redirect(url_for('dashboard'))
        except:
            db.session.rollback()
    
    return render_template('edit_profile.html', form=form)

@app.route('/projects/new', methods=['GET', 'POST'])
@login_required
def create_project():
    if current_user.user_type != 'client':
        return redirect(url_for('dashboard'))

    form = ProjectForm()
    if form.validate_on_submit():
        project = Project(
            client_id=current_user.id,
            title=form.title.data,
            description=form.description.data,
            budget_min=form.budget_min.data,
            budget_max=form.budget_max.data,
            deadline=form.deadline.data,
            expires_at=form.expires_at.data
        )
        try:
            db.session.add(project)
            db.session.commit()
            return redirect(url_for('dashboard'))
        except:
            db.session.rollback()

    return render_template('project_form.html', form=form)

@app.route('/projects/<int:project_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_project(project_id):
    if current_user.user_type != 'client':
        return redirect(url_for('dashboard'))

    project = Project.query.get_or_404(project_id)
    if project.client_id != current_user.id:
        return redirect(url_for('dashboard'))

    form = ProjectForm(obj=project)
    if form.validate_on_submit():
        form.populate_obj(project)
        try:
            db.session.commit()
            return redirect(url_for('dashboard'))
        except:
            db.session.rollback()

    return render_template('project_form.html', form=form, project=project)

@app.route('/projects/<int:project_id>/delete', methods=['POST'])
@login_required
def delete_project(project_id):
    if current_user.user_type != 'client':
        return redirect(url_for('dashboard'))

    project = Project.query.get_or_404(project_id)
    if project.client_id != current_user.id:
        return redirect(url_for('dashboard'))

    try:
        db.session.delete(project)
        db.session.commit()
    except:
        db.session.rollback()

    return redirect(url_for('dashboard'))

@app.route('/projects')
@login_required
def project_list():
    if current_user.user_type != 'engineer':
        return redirect(url_for('dashboard'))

    projects = Project.query.order_by(Project.created_at.desc()).all()
    return render_template('project_list.html', projects=projects)

@app.route('/projects/<int:project_id>')
@login_required
def project_detail(project_id):
    project = Project.query.get_or_404(project_id)
    return render_template('project_detail.html', project=project)

@app.route('/projects/<int:project_id>/apply', methods=['GET', 'POST'])
@login_required
def apply_project(project_id):
    if current_user.user_type != 'engineer':
        return redirect(url_for('dashboard'))

    project = Project.query.get_or_404(project_id)
    existing_proposal = Proposal.query.filter_by(
        project_id=project_id,
        engineer_id=current_user.id
    ).first()
    
    if existing_proposal:
        return redirect(url_for('project_detail', project_id=project_id))

    form = ProposalForm()
    if form.validate_on_submit():
        proposal = Proposal(
            project_id=project_id,
            engineer_id=current_user.id,
            content=form.content.data,
            url=form.url.data,
            expires_at=form.expires_at.data
        )
        try:
            db.session.add(proposal)
            db.session.commit()
            return redirect(url_for('project_detail', project_id=project_id))
        except:
            db.session.rollback()

    return render_template('proposal_form.html', form=form, project=project)

# Initialize database
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='localhost', port=3000, ssl_context=('cert.pem', 'key.pem'), debug=True)
