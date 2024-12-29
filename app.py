import os
from dotenv import load_dotenv
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, IntegerField, DateField
from wtforms.validators import DataRequired, Length, Optional, NumberRange, ValidationError
from flask_migrate import Migrate
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import WebApplicationClient
import hashlib
import logging
from logging.handlers import RotatingFileHandler
import traceback
from datetime import datetime
from functools import wraps
from sqlalchemy import or_
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ログ設定
def setup_logger():
    # ログディレクトリの作成
    if not os.path.exists('logs'):
        os.makedirs('logs')

    # ログフォーマットの設定
    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
    )

    # ファイルハンドラの設定（日付ごとのログファイル）
    file_handler = RotatingFileHandler(
        f'logs/app.log',
        maxBytes=1024 * 1024,  # 1MB
        backupCount=10
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)

    # コンソールハンドラの設定
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.DEBUG)

    # ルートロガーの設定
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger

# ロガーの初期化
logger = setup_logger()

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', os.urandom(24))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET')

# セキュリティ設定
is_production = os.environ.get('RENDER') == 'true'
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # CSRFトークンの有効期限を1時間に設定
app.config['WTF_CSRF_SSL_STRICT'] = is_production  # 本番環境でのみHTTPS強制
app.config['WTF_CSRF_ENABLED'] = True  # CSRFトークンを有効化
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # セッションの有効期限も1時間に設定
app.config['SESSION_COOKIE_SECURE'] = is_production  # 本番環境でのみHTTPS強制
app.config['SESSION_COOKIE_HTTPONLY'] = True  # JavaScriptからのセッションクッキーへのアクセスを防止
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # クロスサイトリクエストを制限

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'index'

# OAuth2 configuration
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
client = WebApplicationClient(app.config['GOOGLE_CLIENT_ID'])

# レート制限の設定
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
    strategy="fixed-window"
)

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

    def validate_expires_at(self, field):
        if field.data and self.deadline.data and field.data > self.deadline.data:
            raise ValidationError('募集期限は納期より前に設定してください')

    def validate_budget_max(self, field):
        if field.data and self.budget_min.data and field.data < self.budget_min.data:
            raise ValidationError('最大金額は最小金額以上に設定してください')

class ProposalForm(FlaskForm):
    content = TextAreaField('提案内容', validators=[DataRequired(), Length(max=2000)])
    url = StringField('提案用URL', validators=[DataRequired(), Length(max=200)])
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

# エラーハンドラ
@app.errorhandler(404)
def not_found_error(error):
    logger.error(f'Page not found: {request.url}')
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    logger.error(f'Server Error: {error}\nTraceback: {traceback.format_exc()}')
    return render_template('errors/500.html'), 500

# レート制限エラーハンドラ
@app.errorhandler(429)  # Too Many Requests
def ratelimit_handler(e):
    logger.warning(f'Rate limit exceeded: {str(e.description)}')
    return render_template('errors/429.html', retry_after=e.description), 429

# ログ記録用のデコレータ
def log_action(action_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                logger.info(f'{action_name} started - User: {current_user.id if not current_user.is_anonymous else "Anonymous"}')
                result = f(*args, **kwargs)
                logger.info(f'{action_name} completed successfully')
                return result
            except Exception as e:
                logger.error(f'{action_name} failed - Error: {str(e)}\nTraceback: {traceback.format_exc()}')
                raise
        return decorated_function
    return decorator

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login/<user_type>')
@log_action('Login attempt')
@limiter.limit("5 per minute")  # ログイン試行の制限
def login(user_type):
    if user_type not in ['client', 'engineer']:
        logger.warning(f'Invalid user type attempted: {user_type}')
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
@log_action('Google OAuth callback')
def callback():
    code = request.args.get("code")
    user_type = request.args.get("state")
    
    if not code:
        logger.warning('No code provided in callback')
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
            logger.warning(f'Unverified email attempted login: {userinfo.get("email")}')
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
            logger.info(f'Existing user logged in: {email} ({user_type})')
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
        logger.info(f'New user registered and logged in: {email} ({user_type})')
        return redirect(url_for('dashboard'))

    except Exception as e:
        logger.error(f'Authentication error: {str(e)}\nTraceback: {traceback.format_exc()}')
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
@log_action('Project creation')
@limiter.limit("10 per hour")  # プロジェクト作成の制限
def create_project():
    if current_user.user_type != 'client':
        logger.warning(f'Non-client user attempted to create project: {current_user.id}')
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
            logger.info(f'Project created successfully: {project.id} by user {current_user.id}')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            logger.error(f'Project creation failed: {str(e)}\nTraceback: {traceback.format_exc()}')

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
@log_action('Project application')
@limiter.limit("20 per hour")  # 提案作成の制限
def apply_project(project_id):
    if current_user.user_type != 'engineer':
        logger.warning(f'Non-engineer user attempted to apply for project: {current_user.id}')
        return redirect(url_for('dashboard'))

    project = Project.query.get_or_404(project_id)
    existing_proposal = Proposal.query.filter_by(
        project_id=project_id,
        engineer_id=current_user.id
    ).first()
    
    if existing_proposal:
        logger.info(f'Duplicate proposal attempted: User {current_user.id} for Project {project_id}')
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
            logger.info(f'Proposal submitted successfully: User {current_user.id} for Project {project_id}')
            return redirect(url_for('project_detail', project_id=project_id))
        except Exception as e:
            db.session.rollback()
            logger.error(f'Proposal submission failed: {str(e)}\nTraceback: {traceback.format_exc()}')

    return render_template('proposal_form.html', form=form, project=project)

# APIエンドポイント
@app.route('/api/projects')
@login_required
@limiter.limit("60 per minute")
def api_projects():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    show_expired = request.args.get('show_expired', 'false') == 'true'
    
    today = datetime.now().date()
    query = Project.query
    
    if not show_expired:
        query = query.filter(or_(
            Project.expires_at.is_(None),
            Project.expires_at >= today
        ))
    
    pagination = query.order_by(Project.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    projects = []
    for project in pagination.items:
        projects.append({
            'id': project.id,
            'title': project.title,
            'description': project.description,
            'budget_min': project.budget_min,
            'budget_max': project.budget_max,
            'deadline': project.deadline.strftime('%Y年%m月%d日') if project.deadline else None,
            'expires_at': project.expires_at.strftime('%Y年%m月%d日') if project.expires_at else None,
            'client': {
                'name': project.client.name,
                'email_hash': hashlib.md5(project.client.email.lower().encode('utf-8')).hexdigest(),
                'picture': project.client.picture
            }
        })
    
    return jsonify({
        'projects': projects,
        'has_more': page < pagination.pages if pagination.pages else False
    })

# Initialize database
with app.app_context():
    db.create_all()

# OAuth2の設定
if not is_production:
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # 開発環境でのみ使用

if __name__ == '__main__':
    if os.environ.get('RENDER'):
        # Production environment (Render)
        port = int(os.environ.get('PORT', 10000))
        app.run(host='0.0.0.0', port=port)
    else:
        # Local development environment
        app.run(host='localhost', port=3000, ssl_context=('cert.pem', 'key.pem'), debug=True)
