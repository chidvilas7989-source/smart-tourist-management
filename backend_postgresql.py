from flask import Flask, request, jsonify, render_template, session, redirect, url_for, send_from_directory
from flask_cors import CORS
import datetime
import uuid
import json
import os
import sys
from functools import wraps
import secrets
from urllib.parse import quote_plus

# Initialize Flask app first
app = Flask(__name__, static_folder='static', template_folder='templates')

# Security Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(hours=24)

# Initialize CORS early
CORS(app, supports_credentials=True)

# Import SQLAlchemy related modules inside try-except to handle compatibility issues
try:
    from flask_sqlalchemy import SQLAlchemy
    from flask_migrate import Migrate
    from werkzeug.security import generate_password_hash, check_password_hash
    from sqlalchemy import text
    import hashlib
    
    # Database configuration only if SQLAlchemy imports successfully
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # PostgreSQL Database Configuration for Render deployment
    DB_USER = os.getenv('DB_USER', 'your_postgres_username')
    DB_PASSWORD = os.getenv('DB_PASSWORD', 'your_postgres_password')
    DB_HOST = os.getenv('DB_HOST', 'your_postgres_host')
    DB_PORT = os.getenv('DB_PORT', '5432')
    DB_NAME = os.getenv('DB_NAME', 'your_database_name')

    # Escape special characters in password for URL encoding
    escaped_password = quote_plus(DB_PASSWORD)

    # Construct PostgreSQL database URI
    DATABASE_URI = f'postgresql+psycopg2://{DB_USER}:{escaped_password}@{DB_HOST}:{DB_PORT}/{DB_NAME}'
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI

    # Production settings for Render
    if os.getenv('RENDER'):
        app.config['DEBUG'] = False
        app.config['SQLALCHEMY_ECHO'] = False
    else:
        app.config['DEBUG'] = True
        app.config['SQLALCHEMY_ECHO'] = True

    # Initialize extensions
    db = SQLAlchemy(app)
    migrate = Migrate(app, db)
    
    # Set database available flag
    DATABASE_AVAILABLE = True
    
except ImportError as e:
    print(f"⚠️  SQLAlchemy import failed: {e}")
    print("🔄 Running in fallback mode without database")
    DATABASE_AVAILABLE = False
    db = None
    migrate = None

# Database Models - Only define if database is available
if DATABASE_AVAILABLE:
    class Admin(db.Model):
        __tablename__ = 'admins'
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(50), unique=True, nullable=False)
        password_hash = db.Column(db.String(255), nullable=False)
        role = db.Column(db.String(20), default='admin')
        created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
        last_login = db.Column(db.DateTime)
        is_active = db.Column(db.Boolean, default=True)

        def set_password(self, password):
            self.password_hash = generate_password_hash(password)

        def check_password(self, password):
            return check_password_hash(self.password_hash, password)

    class Tourist(db.Model):
        __tablename__ = 'tourists'
        id = db.Column(db.Integer, primary_key=True)
        digital_id = db.Column(db.String(20), unique=True, nullable=False)
        name = db.Column(db.String(100), nullable=False)
        contact = db.Column(db.String(20), nullable=False)
        nationality = db.Column(db.String(50), nullable=False)
        registration_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
        status = db.Column(db.String(20), default='active')
        latitude = db.Column(db.Float, default=28.6139)
        longitude = db.Column(db.Float, default=77.2090)
        created_by = db.Column(db.Integer, db.ForeignKey('admins.id'))
        last_updated = db.Column(db.DateTime, default=datetime.datetime.utcnow)

        def to_dict(self):
            return {
                'id': self.id,
                'digital_id': self.digital_id,
                'name': self.name,
                'contact': self.contact,
                'nationality': self.nationality,
                'registration_date': self.registration_date.strftime('%Y-%m-%d'),
                'status': self.status,
                'location': {'lat': self.latitude, 'lng': self.longitude}
            }

    class Officer(db.Model):
        __tablename__ = 'officers'
        id = db.Column(db.Integer, primary_key=True)
        badge_id = db.Column(db.String(20), unique=True, nullable=False)
        name = db.Column(db.String(100), nullable=False)
        rank = db.Column(db.String(50), nullable=False)
        contact = db.Column(db.String(20), nullable=False)
        assigned_zone = db.Column(db.String(50), nullable=False)
        status = db.Column(db.String(20), default='offline')
        registration_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
        latitude = db.Column(db.Float, default=28.6139)
        longitude = db.Column(db.Float, default=77.2090)
        created_by = db.Column(db.Integer, db.ForeignKey('admins.id'))
        last_updated = db.Column(db.DateTime, default=datetime.datetime.utcnow)

        def to_dict(self):
            return {
                'id': self.id,
                'badge_id': self.badge_id,
                'name': self.name,
                'rank': self.rank,
                'contact': self.contact,
                'assigned_zone': self.assigned_zone,
                'status': self.status,
                'registration_date': self.registration_date.strftime('%Y-%m-%d'),
                'location': {'lat': self.latitude, 'lng': self.longitude}
            }

    class Location(db.Model):
        __tablename__ = 'locations'
        id = db.Column(db.Integer, primary_key=True)
        location_id = db.Column(db.String(20), unique=True, nullable=False)
        name = db.Column(db.String(100), nullable=False)
        type = db.Column(db.String(50), nullable=False)
        details = db.Column(db.Text)
        latitude = db.Column(db.Float, nullable=False)
        longitude = db.Column(db.Float, nullable=False)
        date_added = db.Column(db.DateTime, default=datetime.datetime.utcnow)
        status = db.Column(db.String(20), default='active')
        created_by = db.Column(db.Integer, db.ForeignKey('admins.id'))
        last_updated = db.Column(db.DateTime, default=datetime.datetime.utcnow)

        def to_dict(self):
            return {
                'id': self.id,
                'location_id': self.location_id,
                'name': self.name,
                'type': self.type,
                'details': self.details,
                'coordinates': {'lat': self.latitude, 'lng': self.longitude},
                'date_added': self.date_added.strftime('%Y-%m-%d'),
                'status': self.status
            }

    class Alert(db.Model):
        __tablename__ = 'alerts'
        id = db.Column(db.Integer, primary_key=True)
        alert_id = db.Column(db.String(20), unique=True, nullable=False)
        name = db.Column(db.String(100), nullable=False)
        description = db.Column(db.Text)
        sensitivity = db.Column(db.String(20), nullable=False)
        location = db.Column(db.String(100), nullable=False)
        date_created = db.Column(db.DateTime, default=datetime.datetime.utcnow)
        status = db.Column(db.String(20), default='active')
        created_by = db.Column(db.Integer, db.ForeignKey('admins.id'))
        last_updated = db.Column(db.DateTime, default=datetime.datetime.utcnow)

        def to_dict(self):
            return {
                'id': self.id,
                'alert_id': self.alert_id,
                'name': self.name,
                'description': self.description,
                'sensitivity': self.sensitivity,
                'location': self.location,
                'date_created': self.date_created.strftime('%Y-%m-%d'),
                'status': self.status
            }

    class BlockchainID(db.Model):
        __tablename__ = 'blockchain_ids'
        id = db.Column(db.Integer, primary_key=True)
        digital_id = db.Column(db.String(20), unique=True, nullable=False)
        block_data = db.Column(db.JSON)
        hash = db.Column(db.String(64), nullable=False)
        previous_hash = db.Column(db.String(64))
        created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
        verified = db.Column(db.Boolean, default=True)

    # Blockchain Digital ID System
    class DigitalIDBlockchain:
        @staticmethod
        def generate_hash(data):
            return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

        @staticmethod
        def create_digital_id(user_data):
            timestamp = datetime.datetime.utcnow()
            last_record = BlockchainID.query.order_by(BlockchainID.created_at.desc()).first()
            previous_hash = last_record.hash if last_record else '0' * 64

            block_data = {
                'name': user_data.get('name'),
                'contact': user_data.get('contact'),
                'nationality': user_data.get('nationality', 'Unknown'),
                'timestamp': timestamp.isoformat(),
                'previous_hash': previous_hash
            }

            digital_id = 'DID' + str(int(timestamp.timestamp()))[-6:]
            block_data['digital_id'] = digital_id
            block_hash = DigitalIDBlockchain.generate_hash(block_data)

            blockchain_record = BlockchainID(
                digital_id=digital_id,
                block_data=block_data,
                hash=block_hash,
                previous_hash=previous_hash
            )

            db.session.add(blockchain_record)
            db.session.commit()
            return digital_id

# Database Initialization - Only if database is available
def initialize_database():
    """Initialize PostgreSQL database and tables"""
    if not DATABASE_AVAILABLE:
        print("⚠️  Database not available, running in fallback mode")
        return True
        
    try:
        print("=" * 60)
        print("SMART TOURISM SYSTEM - POSTGRESQL DATABASE INITIALIZATION")
        print("=" * 60)

        with app.app_context():
            try:
                db.session.execute(text('SELECT 1'))
                print("✅ PostgreSQL database connection successful")

                db.create_all()
                print("✅ All database tables created successfully")

                init_admin_account()
                print("✅ Database initialization completed successfully!")
                print("=" * 60)
                return True

            except Exception as e:
                print(f"❌ Database initialization failed: {e}")
                return False

    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        return False

def init_admin_account():
    """Initialize admin account"""
    if not DATABASE_AVAILABLE:
        return
        
    try:
        admin = Admin.query.filter_by(username='admin389').first()
        if not admin:
            admin = Admin(username='admin389', role='admin')
            admin.set_password('mont7799')
            db.session.add(admin)
            db.session.commit()
            print("✅ Admin account created (admin389/mont7799)")
        else:
            print("✅ Admin account already exists")
    except Exception as e:
        print(f"❌ Error creating admin account: {e}")

# Authentication decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            return jsonify({'error': 'Admin authentication required', 'authenticated': False}), 401
        return f(*args, **kwargs)
    return decorated_function

# Health check endpoint
@app.route('/api/health', methods=['GET'])
def health_check():
    try:
        database_connected = False
        database_error = None
        
        if DATABASE_AVAILABLE:
            try:
                db.session.execute(text('SELECT 1'))
                database_connected = True
            except Exception as e:
                database_error = str(e)
        
        return jsonify({
            'status': 'healthy' if database_connected or not DATABASE_AVAILABLE else 'degraded',
            'database': 'postgresql' if DATABASE_AVAILABLE else 'unavailable',
            'database_connected': database_connected,
            'database_error': database_error,
            'environment': 'production' if os.getenv('RENDER') else 'development',
            'sqlalchemy_available': DATABASE_AVAILABLE,
            'timestamp': datetime.datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.datetime.utcnow().isoformat()
        }), 500

# Serve HTML Files
@app.route('/')
def serve_admin_portal():
    return send_from_directory('.', 'admin_portal.html')

@app.route('/tourist')
def serve_tourist_portal():
    return send_from_directory('.', 'tourist_portal.html')

@app.route('/officer')
def serve_officer_portal():
    return send_from_directory('.', 'officer_portal.html')

# Basic API routes that work without database
@app.route('/api/status', methods=['GET'])
def api_status():
    return jsonify({
        'status': 'running',
        'database_available': DATABASE_AVAILABLE,
        'timestamp': datetime.datetime.utcnow().isoformat()
    })

# Admin Authentication - Only if database is available
@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    if not DATABASE_AVAILABLE:
        return jsonify({'error': 'Database not available'}), 503
        
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({'error': 'Username and password required', 'authenticated': False}), 400

        admin = Admin.query.filter_by(username=username, is_active=True).first()

        if admin and admin.check_password(password):
            session['admin_id'] = admin.id
            session['admin_username'] = admin.username
            session.permanent = True

            admin.last_login = datetime.datetime.utcnow()
            db.session.commit()

            return jsonify({
                'message': 'Login successful',
                'authenticated': True,
                'admin': {
                    'id': admin.id,
                    'username': admin.username,
                    'role': admin.role
                }
            })

        return jsonify({'error': 'Invalid credentials', 'authenticated': False}), 401

    except Exception as e:
        return jsonify({'error': f'Login failed: {str(e)}', 'authenticated': False}), 500

@app.route('/api/admin/logout', methods=['POST'])
def admin_logout():
    session.clear()
    return jsonify({'message': 'Logout successful', 'authenticated': False})

# Simple fallback routes for when database is not available
@app.route('/api/tourists', methods=['GET'])
def get_tourists():
    if not DATABASE_AVAILABLE:
        return jsonify({'message': 'Database not available', 'data': []}), 503
    
    try:
        tourists = Tourist.query.all()
        return jsonify({'tourists': [t.to_dict() for t in tourists]})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Application entry point
if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))

    # Initialize database if available
    if DATABASE_AVAILABLE:
        if not initialize_database():
            print("⚠️  Database initialization failed, but continuing in fallback mode...")
    
    print("\n" + "="*60)
    print("🚀 SMART TOURISM BACKEND SERVER STARTING")
    print("="*60)

    if os.getenv('RENDER'):
        print("🌐 Production Mode - Render Hosting")
        print(f"🔗 Application URL: Available after deployment")
        if DATABASE_AVAILABLE:
            print("🔌 Database Host:", os.getenv('DB_HOST', 'Unknown'))
            print("🗄️ Database Type: PostgreSQL")
        else:
            print("⚠️  Running without database")
    else:
        print(f"🌐 Development Mode")
        print(f"🌐 Admin Portal: http://localhost:{port}/")
        print(f"🏖️ Tourist Portal: http://localhost:{port}/tourist")
        print(f"👮 Officer Portal: http://localhost:{port}/officer")
        print(f"🏥 API Health Check: http://localhost:{port}/api/health")

    if DATABASE_AVAILABLE:
        print("\n🔐 Admin Credentials:")
        print(" Username: admin389")
        print(" Password: mont7799")
    
    print("="*60)

    try:
        if os.getenv('RENDER'):
            app.run(host='0.0.0.0', port=port, debug=False)
        else:
            app.run(debug=True, host='0.0.0.0', port=port)
    except KeyboardInterrupt:
        print("\n\n👋 Server stopped by user")
    except Exception as e:
        print(f"\n❌ Server error: {e}")
